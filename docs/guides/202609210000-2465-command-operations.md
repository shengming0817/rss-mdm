# 设备状态核实任务（#2465）

## 范围与接口

首个任务类型是 Windows 状态核实。已有注册设备在下一次通过 mTLS 和 SyncML 双向认证的签入中，由任务自身的 Get 读取实际值。支持 `model` 与 `os_version`，值沿用 Inventory 的有界 UTF-8 校验且不裁剪或改写。每个任务核实一个字段；任务本身不修改设备。普通资产采集继续由既有通道负责。

管理请求使用现有 Identity 会话、Origin/CSRF 和设备范围授权。端点为：

| 方法与路径（前缀 `/api/v2/devices/{device}`） | 权限 | 请求 |
|---|---|---|
| POST `/operations` | `state_verify` | `operationId`、`task: {kind:"state_verify",field,expectedValue}`、`deadline`（Unix 秒） |
| GET `/operations/{id}` | `operation_read` | 无 |
| POST `/operations/{id}/cancel` | `operation_cancel` | `requestId`、`expectedRevision` |
| POST `/operations/{id}/approve` | `state_verify` | `requestId`、`expectedRevision` |

创建返回 202 和稳定 operation/command 标识。请求 UUID 在租户内唯一；同键同主体同内容重放原回执，异内容返回 409。批准不改变原任务、期限或 command；已取消、超时、拒绝、取代或完成的任务不能重新批准。模型与 OS 版本使用同一套授权及生命周期，没有任意 URI、脚本或原生命令上传入口。

本地用户、用户组、IdP 组和部门均通过现有授权器生成任务批准。派发重新检查批准所依赖的规则版本、用户组成员和外部证据有效期；原依据失效即阻塞，需要有权主体显式重新批准。批准不保存会话秘密，不依赖浏览器保持连接。任务批准也不替代后续危险动作所需的专用执行批准。

## 结果与恢复

`queued` 是持久受理；`published` 是精确 Outbox 消息已由产品网关持久接纳；`received` 是关联的原生 Get 成功 Status；`applied` 仅在关联实际 Results 校验并匹配预期摘要后出现。查询中的观察结果另外区分 `unknown`、`mismatched` 和 `matched`，并提供 attempt、原生关联 ID、原生状态与实际值。

不匹配继续等待后续签入。每个 command 至多一个未结束的 attempt；新尝试沿用 operation/command，分配新的 attempt 与原生关联 ID。提前到达的 Results 由命令 attempt 保存，在对应 Status 到达前不标记匹配成功。旧尝试、错误注册或乱序消息不能覆盖当前结果。

任务在管理响应编码前生成自身 Get 并持久化关联。合法缓存重放沿用已有 attempt；不能把受理前或批准失效期间发出的普通 Inventory Get 事后绑定给新任务。旧读数仍可作为 Inventory 观察保留，但不完成新任务。

取消、过期和撤权阻止后续任务投递；含失效任务的缓存响应也拒绝重放。已经发出的合法回执仍可保留；服务端终态不表示终端撤销、停止或效果回滚。会话缓存可清理，任务关联与历史证据保留。

503 `operation_unknown` 表示提交可能完成。保留原请求及 UUID，先 GET 查询并以完全相同的请求重试；暂时 404 也不构成回滚证明。不要生成替代 operation。后台恢复由 RSS reconcile 的持久唤醒/租约和 device-command 的有界恢复提供，组件状态没有产品副本。worker 生命周期可无限等待并由运行时取消；每次存储操作仍使用有限预算，不能把无限预算直接转换为平台无法表示的 Instant。

命令连接配置是必填 `command_database`，使用 `mdm_command_runtime`，与产品其他连接指向同一数据库。完整配置见 `fixtures/mdm-config.example.json`。命令 store 与 Outbox 共享精确同一 messaging runtime；Windows 会话、命令回执和成功审计借用同一事务。Observation 接收与 Inventory 投影仍有各自事务，任务核实不宣称投影或合规已经完成。

## 请求与响应契约

创建请求示例（截止时间须替换为未来的 Unix 秒）：

```json
{"operationId":"a2998159-d1b6-4e8a-87d1-6253367530e9","task":{"kind":"state_verify","field":"model","expectedValue":"Surface Pro"},"deadline":1800000000}
```

成功返回 `202`：

```json
{"operationId":"a2998159-d1b6-4e8a-87d1-6253367530e9","commandId":"a2998159-d1b6-4e8a-87d1-6253367530e9","revision":1,"accepted":true}
```

`operationId`/`requestId` 是非零 UUID。`field` 仅接受 `model` 或 `os_version`；`expectedValue` 是字段允许的非空字符串。所有请求拒绝未知字段。取消与重新批准使用独立请求：

```json
{"requestId":"05b31cc6-d0a4-4e97-819d-c06b8f3b1ded","expectedRevision":1}
```

成功返回 `200 {"operationId":"…","revision":2}`。版本是任务批准/取消版本，不是 RSS command version；查询获得当前版本后再提交。精确重放返回原版本回执。

查询成功返回 `200`，字段为 `operationId`、`commandId`、`revision`、`task`、`deadline`、`authorization`、`commandStatus`、`observation`。任务规格始终是受理时的不可变内容。`authorization` 为 `approved` 或 `blocked`，不代表 command 已执行。`commandStatus` 枚举为 `queued`、`published`、`received`、`applied`、`rejected`、`timed_out`、`superseded`、`cancelled`。

Windows observation 带 `protocol:"mdm.windows"`；Apple 的 Profile 存在性结果见 [Apple 指南](202609230000-2471-apple-management.md)。尚未发出尝试时，`observation` 包含 `result/effect/progress=unknown` 及 `writeStatus=null`。已有尝试时包含：

| 字段 | 类型及含义 |
|---|---|
| `attemptId` | UUID 字符串，最新原生尝试 |
| `attempt` | 从 1 开始的整数 |
| `result` | `unknown`、`mismatched`、`matched` |
| `quality` | `pending`、`success`、`failed`、`unsupported` |
| `nativeStatus` | 原生 Status 整数；未收到为 null |
| `value` | 原生字段字符串；未收到为 null |
| `effect`、`progress`、`writeStatus` | 效果核验、执行进度和独立写回执；设备整体观察不能证明防火墙配置效果 |
| `receivedAt` | 接收时间 Unix 秒；未收到为 null |

业务错误响应为 `{"code":"…"}`。JSON 反序列化错误统一为 400 `malformed_request`；400 表示字段/期限无效；401 表示身份无效；403 表示缺权限、批准失效或禁止缓存投递；404 表示产品任务不存在；409 表示幂等冲突、版本冲突或终态不能再批准。503 `service_unavailable` 包括依赖故障及已存在任务缺失关联 command 等存储不变量损坏，不能当作任务不存在重建。503 `operation_unknown` 按原身份查询和精确重放。

relay 对可恢复故障按 1–60 秒退避；提交未知保留原消息和身份。非法消息身份、指纹冲突或存储不变量损坏使关键 worker 失败，由统一运行时关闭并报告，修复存储后重启。诊断包含阶段、原因及合法消息 UUID；reconcile 诊断带设备 scope 的摘要标识。不得通过更换任务 ID 绕过损坏。

事务准入的 `catalog.json` / `dependencies.json` 是固定依赖版本及迁移的 catalog 契约，包含所用表的约束/策略和 RSS 函数定义/ACL，不包含业务数据。`make command-catalog`（或 `python3 hack/command_catalog.py --check`）在独立 TLS PostgreSQL 容器中执行候选迁移，以固定 `mdm_command_runtime` 角色和 `pg_catalog` search path 读取 commands/catalog、commands/dependencies、management/catalog 三份契约并比较；差异即失败，完整 CI 包含此门禁。

依赖或迁移明确变更后，运行 `python3 hack/command_catalog.py --write`，审核并提交三份 JSON。输出统一排序，每份文件以临时文件原子替换；生成器没有生产连接参数，不读取生产业务数据，也不从运行期漂移自动学习新契约。

## 后续消费者的设计样本

#2466 的状态型命令：防火墙配置写入使用其固定 DDF/CSP 编译结果；同一逻辑 command 可以关联多个原生 CmdID。写入的 Status 只证明协议结果，另一个 Get/Results 提供实际值；需要 Atomic 的规则载荷由 Windows 配置 owner 决定。#2466 已新增受限 Replace；该防火墙叶不可 Get，独立设备级读数不证明叶值。

#2468 的动作型任务样本：`operation=script-run-1`、`command=script-run-1:execute`、`attempt=1`，载荷绑定资源版本、设备注册、用途、摘要与期限；`ack=received` 和 `result={exitCode:0,outputDigest:…}` 是不同事实。退出码不是状态摘要，不能转换为 device-command 的 `Applied`。脚本 ActionRun、共享 Agent wire、内容交付及调度由后续 owner 实现。

## 验证入口

`python3 hack/command-t2.py` 使用真实 TLS PostgreSQL、真实产品 Router/Identity 管理 HTTP、真实注册证书和受控 SyncML 客户端；源码与受测 HEAD 由完整 `make ci` 绑定。它验证服务端接缝，不能代替真实 Windows T3，也不宣称 OS 状态或脚本效果已经在真机验证。

参考：[Windows OMA DM](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support)、[SQLx v0.9.0 事务源码](https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-core/src/transaction.rs)。

#2466 的单向升级及防火墙消费者见[Windows 配置指南](202609220000-2466-windows-firewall.md)。旧平铺任务请求和事后绑定 Inventory 的执行路径已退出。
