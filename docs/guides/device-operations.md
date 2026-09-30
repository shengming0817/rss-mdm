# 设备操作与 Windows 防火墙

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

命令连接配置是必填 `execution.database`，使用 `mdm_command_runtime`，与产品其他连接指向同一数据库。完整配置见 `fixtures/mdm-config.example.json`。命令 store 与 Outbox 共享精确同一 messaging runtime；Windows 会话、命令回执和成功审计借用同一事务。Observation 接收与 Inventory 投影仍有各自事务，任务核实不宣称投影或合规已经完成。
## Windows 防火墙

### 能力与证据

唯一写节点为 `./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall`，输入 `enabled: bool`，编译器固定产生 Replace/bool/true 或 false。所选微软 DDF 仅支持 Replace，不支持该 leaf 的 Get/Delete；取消不回滚，也不恢复猜测的原值。

独立 Get 读取 `./Vendor/MSFT/DeviceStatus/Firewall/Status`：0 开启并监控，1 禁用，2 部分网络或规则未监控，3 暂时未完整监控，4 不适用。这个值属于设备整体，不能证明 DomainProfile 值或本次策略效果。写入回执与观察分开记录；写入成功后配置 `effect` 始终为 `unknown`，cleanup 为 `unsupported`，不能升级为 Applied、VerifiedPresent 或合规。命令传输进度与可证明的设备效果分别展示。

固定来源为 [Microsoft DDF v2 February 2026](https://download.microsoft.com/download/015bd9f5-9cca-4821-8a85-a4c5f9a5d0f2/DDFv2Feb2026.zip)。来源文件、摘要和裁剪目录位于 `crates/windows-mdm/ddf/`；`tests/test_ddf.py` 从已校验原始节点及祖先适用性独立重建目录。生产不联网解析 DTD，不接收 XML/URI/操作上传。WinMDM 历史 `application/provider/windows_firewall.go` 仅作 Replace bool 来源对照，不继承 warning-mode 验证或其他 profile/rule。

平台预检要求设备级 Windows 管理、版本至少 10.0.16299，edition 属于固定 DDF allow-list。OS version 与 edition 从当前注册世代的认证 SyncML Get 获取；派发前要求本次会话再次提供一致事实。报告有设备来源，但不等同于硬件证明。未知、不适用及世代变化拒绝写入。真实 OS 行为须由设备 T3 验收，受控协议 T2 不代表真机效果。
### 产品接口

管理接口沿用 Identity 会话、Origin/CSRF 与产品授权。Resource 使用 `/api/v3`；Scope、Policy、远程操作和设备 operation 使用 `/api/v2`。

1. `POST /api/v3/resources/{id}` 创建 configuration resource，再提交 `input: {action:"firewall_version", version:"v1", enabled:true}` 并 activate 资源版本。外层为 `operationId/expectedRevision/input`；版本内容不可变。
2. `POST /api/v2/policies/{id}` 发布 `action: put`，绑定 resource 的平台与 variant、持续 Scope（显式设备由 Scope 直接来源表达），定义中的 `action: {kind:"configuration",resource:{...},exit:"retain"}`。Windows 防火墙不支持 remove；macOS profile 可使用受支持的 remove。
3. 相关成员、版本、注册或能力变化自动触发差分核对；没有保存 Plan 或人工 execute 步骤。`GET /api/v2/policies/{id}/devices` 分页返回当前资格、阻断诊断和必要的 operation 引用。
4. 使用 `/api/v2/devices/{device}/operations/{operation}` 查询原生命令及观察。Policy 子命令不能通过重新批准脱离分配约束。修改或停用 Policy 使用配置 CAS，设备回执不推进该 CAS。

发布需要租户级 `policy_write` 和目标的 `firewall_write`；Scope 分配还需要 `scope_read` 与全设备写权限。发布后的分配归组织持有，发布者岗位、会话和授权规则变化不撤销分配。设备世代、资源、能力和当前 Scope 仍在交付时验证。

同效果的配置分配共享必要命令，退出一个分配不会移除其他分配仍需要的效果。相反效果报告 `configuration_conflict`；缺少注册、能力或新鲜 Scope 时分别保留 `waiting_registration`、`waiting_capability`、`waiting_scope`，相关输入更新后自动重试。固定 DDF 不适用时报告 `not_applicable`。分配状态与某次命令的失败、期限、回执及观察分开。

一次性操作使用 `POST /api/v2/remote-operations`，绑定不可变资源、设备或当前 Scope、`action: {kind:"apply_configuration"}` 和 deadline。受理时固定本次目标，后台分页创建必要的原生子命令；逐设备阻断不使其他设备丢失执行机会。它不创建长期 Policy，也不参与持续分配的自动退出。请求恢复和取消见 [Group、Scope 与 Policy](groups-scopes-policies.md)。

命令、执行授权、审计和 Outbox 共用事务。Policy core/adapter 持有唯一分配模型与存储；应用组合资源、Scope 和通道，运行角色通过精确只读合同读取分配与目标证据，并继续使用原生命令 owner 的写入路径。

### 原生生命周期

Inventory 与任务各自产生请求，由同一管理响应 owner 分配不冲突的 CmdID 并最终编码、缓存。任务在编码前持久化关联；没有事后认领普通 Inventory Get 的路径。写入最终成功回执停止 Replace，下一条独立 Get 获取粗粒度观察。缺失写入回执保留未知，不盲目重发。观察结束或达到期限后不持续轮询。

能力查询记录通过延迟校验外键绑定管理 session；retention 删除过期 session 时同事务级联清理查询。清理失败整体回滚并沿用 session retention 失败诊断；持久能力事实与命令回执保留。尝试阶段仅允许 `execute` / `observe`，未知存储值拒绝解释。

原生关联绑定 tenant/device/registration generation/credential/session/message/command/attempt。回执、观察和底层命令终态分别保存；旧尝试和迟到消息不推进新版本命令。底层命令到期不能覆盖已有写入回执。只有当时有效的原生成功回执（`receiptAccepted: true`）产生 `progress: succeeded`；迟到回执单独留存。观察缺失到期为 `quality: missing`，不改变既有写入成功或 unknown 效果。取消返回实际命令状态；历史终态不会被改写成 cancelled。

安装、升级和后台诊断见 [运维](../deployment/operations.md)。ActionRun 与状态型任务分离，脚本退出码不能转成 Applied；见 [企业任务](enterprise-tasks.md)。

## 设备时间线

管理员通过 `GET /api/v3/devices/{device}/timeline` 检索现有注册、凭据、资产和管理审计事实，可用 `operationId` 和时间区间筛选。入口复用现有管理读取能力；不需要额外申请时间线权限。时间线只呈现已经持久化的事实，受理、请求结算、执行状态和实际效果分别解释；缺失结果保持未知，202 不表示设备执行成功。

排序使用持久记录时间，发生时间另行显示。分页使用响应中的签名游标和相同筛选条件；第一页固定上界，新事实需要重新查询。响应的覆盖进度说明索引追赶情况，未完成追赶不表示设备没有历史事件。字段、筛选和预算的唯一契约见 [timeline-service](../../crates/timeline-service/src/model.rs)。

未保存可信设备关联的历史事实不推测归属，仍可从管理审计入口按 operation 查阅。覆盖进度只说明源记录索引进度，不证明设备生命周期或所有业务阶段齐全。
