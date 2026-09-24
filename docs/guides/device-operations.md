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

命令连接配置是必填 `command_database`，使用 `mdm_command_runtime`，与产品其他连接指向同一数据库。完整配置见 `fixtures/mdm-config.example.json`。命令 store 与 Outbox 共享精确同一 messaging runtime；Windows 会话、命令回执和成功审计借用同一事务。Observation 接收与 Inventory 投影仍有各自事务，任务核实不宣称投影或合规已经完成。
## Windows 防火墙

### 能力与证据

唯一写节点为 `./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall`，输入 `enabled: bool`，编译器固定产生 Replace/bool/true 或 false。所选微软 DDF 仅支持 Replace，不支持该 leaf 的 Get/Delete；取消不回滚，也不恢复猜测的原值。

独立 Get 读取 `./Vendor/MSFT/DeviceStatus/Firewall/Status`：0 开启并监控，1 禁用，2 部分网络或规则未监控，3 暂时未完整监控，4 不适用。这个值属于设备整体，不能证明 DomainProfile 值或本次策略效果。写入回执与观察分开记录；写入成功后配置 `effect` 始终为 `unknown`，cleanup 为 `unsupported`，不能升级为 Applied、VerifiedPresent 或合规。执行与设备效果采用既有 Policy Progress/Effect 语义。

固定来源为 [Microsoft DDF v2 February 2026](https://download.microsoft.com/download/015bd9f5-9cca-4821-8a85-a4c5f9a5d0f2/DDFv2Feb2026.zip)。来源文件、摘要和裁剪目录位于 `crates/windows-mdm/ddf/`；`tests/test_ddf.py` 从已校验原始节点及祖先适用性独立重建目录。生产不联网解析 DTD，不接收 XML/URI/操作上传。WinMDM 历史 `application/provider/windows_firewall.go` 仅作 Replace bool 来源对照，不继承 warning-mode 验证或其他 profile/rule。

平台预检要求设备级 Windows 管理、版本至少 10.0.16299，edition 属于固定 DDF allow-list。OS version 与 edition 从当前注册世代的认证 SyncML Get 获取；派发前要求本次会话再次提供一致事实。报告有设备来源，但不等同于硬件证明。未知、不适用及世代变化拒绝写入。真实 OS 行为须由设备 T3 验收，受控协议 T2 不代表真机效果。
### 产品接口

管理接口沿用 Identity 会话、Origin/CSRF 与产品授权。Scope、Policy 与候选预览路径前缀 `/api/v2`；Resource 路径前缀为 `/api/v3`；执行和设备 operation 使用 `/api/v2`。

1. `POST /resources/{id}` 创建 configuration resource，再提交 `input: {action:"firewall_version", version:"v1", enabled:true}`。外层仍为 `operationId/expectedRevision/input`；版本内容不可变。
2. `POST /policies/{id}` 创建并 activate 对应 resource/resourceVersion。
3. `POST /policies/{id}/previews` 返回异步 task/statusUrl。轮询 task 完成后，`execution` 提供冻结 Scope、资源版本、DDF、注册及能力证据；`policyRevision` 是保存所需 CAS token（导入命令执行事实可能推进 revision）。`POST /policies/{id}/plans` 使用此 revision 保存同一 task。
4. `POST /policies/{id}/plans/{preview}/execute` 接收 `operationId/expectedRevision/deadline`，其中 revision 是保存回执的 storageRevision，deadline 为 Unix 秒。成功返回稳定的逐设备 operation/command 引用；重放必须保留原主体、请求和计划。
5. 使用现有 `/devices/{device}/operations/{operation}` 查询、取消和重新批准。不能通过直接创建任务接口绕过冻结计划写防火墙。

执行要求租户级 `plan_execute` 和全部目标（含退出/归档目标）的设备级 `firewall_write`；取消意图还要求同一设备的 `operation_cancel`，首次执行与重放均重新检查这两项权限。state_verify、policy_write、plan_save 均不能替代写权限。批准记住具体权限及依据，派发重新核验；撤权、期限或旧世代不能由缓存重放绕过。

Management 持有类型化 `PlanExecutionAdmission`，从 Policy 公共分页接口冻结执行输入；同一个 owner 准入投影服务保存、执行、投递、缓存重放、回执及恢复。Policy 持有候选/版本/来源 token 的有效性，Management 组合 Scope 和尚未转发的设备身份历史。Commands 仅调用窄投影，运行角色没有 Management、Policy、Group 私表 SELECT 权限。

冻结计划使用闭合动作与原因类型，未知动作、未知原因和多余字段拒绝解析。所有首次执行（包括仅取消和空动作）在任何写入前检查 deadline 未过期且微秒换算不溢出；已提交请求重放保留原结果并重新校验权限。

计划执行、命令、批准、审计、Outbox 共用事务。每次首次成功执行写入一条 `plan_execute` 审计，关联请求、策略和计划；仅取消及空动作同样记录，失败事务不保留成功审计。任一目标不满足条件则整批拒绝。配置计划使用独立执行预算，超限明确拒绝；预算由应用配置准入源码持有。数据库唯一键持有租户/设备/固定配置节点的策略归属；命令终态不会释放归属，只有执行归属策略的退出/归档计划才释放。不同策略不能争用同一设备的活动防火墙配置；同策略新版本取消旧任务并生成新冻结命令。命令运行角色仍是 RSS device-command 的唯一运行消费者，管理角色通过命令 owner 的只读 policy_facts 接缝获取事实。

预览、保存和执行的配置失败使用闭合错误码：`capability_unknown`（缺少当前能力）、`platform_unsupported`（固定 DDF 不适用）、`stale_plan`（冻结依据已变化）、`owner_conflict`（节点归属冲突）。预览失败保存在 task 的 `failure` 和 `failureDetail`；保存/执行用 HTTP 409。详情携带 `stage: preview|save|execute` 和可定位时的 `device`；计划级变化的 device 为 null，不返回私表或原始报告。
### 原生生命周期

Inventory 与任务各自产生请求，由同一管理响应 owner 分配不冲突的 CmdID 并最终编码、缓存。任务在编码前持久化关联；没有事后认领普通 Inventory Get 的路径。写入最终成功回执停止 Replace，下一条独立 Get 获取粗粒度观察。缺失写入回执保留未知，不盲目重发。观察结束或达到期限后不持续轮询。

能力查询记录通过延迟校验外键绑定管理 session；retention 删除过期 session 时同事务级联清理查询。清理失败整体回滚并沿用 session retention 失败诊断；持久能力事实与命令回执保留。尝试阶段仅允许 `execute` / `observe`，未知存储值拒绝解释。

原生关联绑定 tenant/device/registration generation/credential/session/message/command/attempt。回执、观察和底层命令终态分别保存；旧尝试和迟到消息不推进新计划。底层命令到期不能覆盖已有写入回执。只有当时有效的原生成功回执（`receiptAccepted: true`）产生 `progress: succeeded`；迟到回执单独留存。观察缺失到期为 `quality: missing`，不改变既有写入成功或 unknown 效果。计划取消结果返回 `action: cancel` 与实际 `commandStatus`；历史终态不会被改写成 cancelled。

安装、升级和后台诊断见 [运维](../deployment/operations.md)。ActionRun 与状态型任务分离，脚本退出码不能转成 Applied；见 [企业任务](enterprise-tasks.md)。
