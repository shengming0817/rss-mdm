# 设备状态核实任务（#2465）

## 范围与接口

首个任务类型是 Windows 状态核实。已有注册设备在下一次通过 mTLS 和 SyncML 双向认证的签入中，以新的 CollectionRun 读取实际值。支持 `model` 与 `os_version`，值沿用 Inventory 的有界 UTF-8 校验且不裁剪或改写。每个任务核实一个字段；任务本身不修改设备。普通资产采集继续由既有通道负责。

管理请求使用现有 Identity 会话、Origin/CSRF 和设备范围授权。端点为：

| 方法与路径（前缀 `/api/v1/devices/{device}`） | 权限 | 请求 |
|---|---|---|
| POST `/operations` | `state_verify` | `operationId`、`field`、`expectedValue`、`deadline`（Unix 秒） |
| GET `/operations/{id}` | `operation_read` | 无 |
| POST `/operations/{id}/cancel` | `operation_cancel` | `requestId`、`expectedRevision` |
| POST `/operations/{id}/approve` | `state_verify` | `requestId`、`expectedRevision` |

创建返回 202 和稳定 operation/command 标识。请求 UUID 在租户内唯一；同键同主体同内容重放原回执，异内容返回 409。批准不改变原任务、期限或 command；已取消、超时、拒绝、取代或完成的任务不能重新批准。模型与 OS 版本使用同一套授权及生命周期，没有任意 URI、脚本或原生命令上传入口。

本地用户、用户组、IdP 组和部门均通过现有授权器生成任务批准。派发重新检查批准所依赖的规则版本、用户组成员和外部证据有效期；原依据失效即阻塞，需要有权主体显式重新批准。批准不保存会话秘密，不依赖浏览器保持连接。任务批准也不替代后续危险动作所需的专用执行批准。

## 结果与恢复

`queued` 是持久受理；`published` 是精确 Outbox 消息已由产品网关持久接纳；`received` 是关联的原生 Get 成功 Status；`applied` 仅在关联实际 Results 校验并匹配预期摘要后出现。查询中的观察结果另外区分 `unknown`、`mismatched` 和 `matched`，并提供 attempt、CollectionRun、原生状态与实际值。

不匹配继续等待后续签入。每个 command 至多一个未结束的 attempt；新尝试沿用 operation/command，分配新的 attempt 与 CollectionRun。提前到达的 Results 由 CollectionRun 保存，在对应 Status 到达前不标记匹配成功。旧尝试、错误注册或乱序消息不能覆盖当前结果。

取消、过期和撤权阻止后续任务投递；含失效任务的缓存响应也拒绝重放。已经发出的合法回执仍可保留；服务端终态不表示终端撤销、停止或效果回滚。会话缓存可清理，任务关联与 CollectionRun 证据保留。

503 `operation_unknown` 表示提交可能完成。保留原请求及 UUID，先 GET 查询并以完全相同的请求重试；暂时 404 也不构成回滚证明。不要生成替代 operation。后台恢复由 RSS reconcile 的持久唤醒/租约和 device-command 的有界恢复提供，组件状态没有产品副本。

命令连接配置是必填 `command_database`，使用 `mdm_command_runtime`，与产品其他连接指向同一数据库。完整配置见 `fixtures/mdm-config.example.json`。命令 store 与 Outbox 共享精确同一 messaging runtime；Windows 会话、命令回执和成功审计借用同一事务。Observation 接收与 Inventory 投影仍有各自事务，任务核实不宣称投影或合规已经完成。

## 后续消费者的设计样本

#2466 的状态型命令：防火墙配置写入使用其固定 DDF/CSP 编译结果；同一逻辑 command 可以关联多个原生 CmdID。写入的 Status 只证明协议结果，另一个 Get/Results 提供实际值；需要 Atomic 的规则载荷由 Windows 配置 owner 决定。本项只实现已有 Get profile，不将样本解释为写入能力已开放。

#2468 的动作型任务样本：`operation=script-run-1`、`command=script-run-1:execute`、`attempt=1`，载荷绑定资源版本、设备注册、用途、摘要与期限；`ack=received` 和 `result={exitCode:0,outputDigest:…}` 是不同事实。退出码不是状态摘要，不能转换为 device-command 的 `Applied`。脚本 ActionRun、共享 Agent wire、内容交付及调度由后续 owner 实现。

## 验证入口

`python3 hack/command-t2.py` 使用真实 TLS PostgreSQL、真实产品 Router/Identity 管理 HTTP、真实注册证书和受控 SyncML 客户端；源码与受测 HEAD 由完整 `make ci` 绑定。它验证服务端接缝，不能代替真实 Windows T3，也不宣称 OS 状态或脚本效果已经在真机验证。

参考：[Windows OMA DM](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support)、[SQLx v0.9.0 事务源码](https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-core/src/transaction.rs)。
