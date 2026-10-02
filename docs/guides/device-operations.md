# 设备操作与 Windows 防火墙

## 范围与接口

`GET /api/v2/operations` 查询现有命令与 Agent action run，支持 `device/kind/policy/remoteOperation/status`
筛选，以及 `limit`（默认 64、1–1000）和 `descending`。`nextCursor` 包含 `id/kind`，续页同时传入
`after/afterKind`，避免两种执行记录使用相同 UUID 时丢失记录。统计与列表候选使用同一次数据库读取，
先按当前 `operation_read` 设备范围限制；摘要不返回原始输出和诊断流，通过 `detailUrl` 下钻既有接口。

`GET /api/v2/remote-operations` 提供一次性操作目录，可按 `resource/kind/cancelled` 筛选，
支持 `limit/after/descending`。显式设备快照须全部可读，Scope 快照沿用全设备读取要求。
普通脚本计划使用执行型 Policy 和一次性操作目录，没有独立 ScriptPlan。

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

命令连接配置是必填 `execution.database`，使用 `mdm_command_runtime`，与产品其他连接指向同一数据库。完整配置见 `fixtures/mdm-config.example.json`。命令 store 与 Outbox 共享精确同一 messaging runtime；Windows 会话、命令回执和成功审计借用同一事务。Observation 接收与 Inventory 投影仍有各自事务，任务核实不宣称投影或合规已经完成。
## Windows 原生操作

Windows 使用固定 DDF/CSP/ADMX 来源和 Node/Atomic/Sequence 类型化操作树，通过现有 Resource/Policy/Scope 和受保护执行路径管理对象。动态身份、设备/用户 scope、build/edition 和实际操作权限分别校验；客户端不提供可信平台或权限事实。

Resource 元数据入口为 `/api/v4/resources/{id}`，配置内容通过既有 `/api/v3/resources/{id}/content` 上传并保护。Policy、远程操作及设备 operation 使用 `/api/v3`。配置内容示例：

```json
{"target":{"kind":"device"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana","instance":[],"operation":"replace","value":{"type":"integer","value":"1"}}}},"remove":null}
```

Policy 引用精确资源版本/variant；它消费完整操作权限和多对象 claims。软件原生 MSI 输入保持通用，但产品安装准入只允许既有固定 Agent。安全 Policy、证书及凭据载体要求对应 SecurityOperate/Credentials，不能以 configuration_write 或 inventory_collect 绕过。

查询分别返回原生 receipts、执行进度、effect 和 effectReason。ACK 不证明效果；效果为 verified、diverged、waiting 或 unverifiable。DomainProfile/EnableFirewall 仍只有原生 Replace，DeviceStatus 的设备整体状态不能证明该叶效果。Policy Delete 可能恢复默认值；缺少固定检测条件时保留 unverifiable 和 guards，超时/取消不重发已派发未知变更。

机器来源、逐文件摘要和归档摘要分别固定；生成/更新命令见[本地开发](local-development.md)。原始请求、回执和关联绑定租户、设备、注册世代及操作身份并加密保存。用户/linked 身份维护、持续配置、会话增强与诊断制品由对应生命周期 owner 提供；必要前提缺失只拒绝相关操作。受控协议验证不代表真机效果或合规。

安装、升级和后台诊断见[运维](../deployment/operations.md)。ActionRun 与状态型任务分离，脚本退出码不转成变更效果；见[企业任务](enterprise-tasks.md)。

## 设备时间线

管理员通过 `GET /api/v3/devices/{device}/timeline` 检索现有注册、凭据、资产和管理审计事实，可用 `operationId` 和时间区间筛选。入口复用现有管理读取能力；不需要额外申请时间线权限。时间线只呈现已经持久化的事实，受理、请求结算、执行状态和实际效果分别解释；缺失结果保持未知，202 不表示设备执行成功。

排序使用持久记录时间，发生时间另行显示。分页使用响应中的签名游标和相同筛选条件；第一页固定上界，新事实需要重新查询。响应的覆盖进度说明索引追赶情况，未完成追赶不表示设备没有历史事件。字段、筛选和预算的唯一契约见 [timeline-service](../../crates/timeline-service/src/model.rs)。

未保存可信设备关联的历史事实不推测归属，仍可从管理审计入口按 operation 查阅。覆盖进度只说明源记录索引进度，不证明设备生命周期或所有业务阶段齐全。
