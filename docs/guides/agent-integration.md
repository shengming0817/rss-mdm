# Agent 注册与报告

服务端接入使用 [agent-wire](../../crates/agent-wire/README.md) 的闭合协议，版本、schema 和能力形态由协议包唯一持有。Agent 实现位于独立仓库；本指南不证明终端采集或执行已验收。

## 注册

管理员先按 [Enrollment 与审计](device-enrollment.md) 创建 `source: "agent.builtin"` 的授权，并把 enrollmentId 与一次性口令安全交给设备。Agent 自行生成另一个 32 字节随机值作为长期 credential，然后发送：

```json
{
  "wireVersion": 5,
  "operationId": "非 nil UUID",
  "enrollmentId": "管理员返回的 UUID",
  "password": "43 字符无填充 Base64URL",
  "credential": "另一个 43 字符无填充 Base64URL",
  "platform": "macos",
  "architecture": "aarch64",
  "capabilities": ["inventory.collect.v5"]
}
```

V5 capability 按顺序声明库存基础能力，以及脚本 `task.execute.v5`、软件 `software.execute.v5` 中实际支持的能力；还可声明标准注册入口能力 `mdm.enrollment.v5`，能力按协议规定顺序排列。仅库存注册访问任务返回 permission denied。平台和架构绑定在注册世代中，服务端据此选择精确任务变体，Agent 仍须用本机真实 OS/架构核验签名任务；声明本身不是受检硬件事实。V4 及更早请求和路由不接受，不提供旧版解码或降级执行。

`POST /api/agent/v5/registrations` 仅接受 `Content-Type: application/json`，成功首次提交返回 201，精确重放返回 200；同 operationId 改变内容返回 409。绑定事务同时验证原管理员当前会话和 enrollment 权限、channel、口令版本、期限与世代，保存注册/来源/capability/成功审计并将 Enrollment 标为 bound。数据库只保存 tenant 域隔离的 SHA-256 locator，不保存 credential 明文。

同一设备再次完成 Agent 注册会建立下一世代并原子停用旧注册、旧 credential 和旧来源。MDM channel 世代相互独立。管理员撤销仍使用 `/api/v3/devices/{device}/registrations/{registration}/revoke` 和独立 `credentials` 权限。
## 报告与状态

报告请求使用严格的 `Authorization: Bearer <credential>`。V5 注册回执的 `collections` 返回服务端选择的冻结采集定义；报告必须携带对应完整 `collection` 对象，以及 wireVersion、reportId、sequence、observedAt、body。Agent 按 dataset 选择回执中的定义，不能自行增加字段或来源。普通字段值示例：

```json
{"field":"device.model","value":{"kind":"value","value":{"kind":"string","value":"Model A"}}}
```

snapshot、partial、failed 分别表达完整快照、部分结果和失败。空的成功快照与未执行、失败不同。通道状态也使用目录中声明的普通字段；不存在 `mdmEnrollment` 报告特例。字段身份、类型、来源和预算由冻结的定义决定，重复字段、定义外字段和未知 JSON 成员被拒绝。`POST /api/agent/v5/reports` 在不可变报告、摘要和成功审计提交后返回 202/durable；相同 reportId 与相同语义返回原 receivedAt，不同语义返回 409。

待投递报告达到有界容量时返回 service_unavailable，优先恢复既有 reportId。历史裁剪不得删除 pending 报告。Agent 与 Windows MDM 均由 `collection_runs` 持有不可变报告和最小交付进度，不存在第二套报告队列或 owner 分支。

恢复及 Agent 状态读取共同核对持久报告的 tenant、registration、source、epoch、dataset、reportId、sequence、coverage、规范字节和摘要，并要求报告已封存；数据库关系列与冻结报告内容不一致时拒绝恢复。

后台沿用唯一的 Inventory 运行时：保存不可变完整 CollectionRun 结果，通过有界摘要引用提交 Observation。产品投影验证引用和来源后应用成功字段；部分结果与失败不能清空旧事实，只有完整快照或显式 tombstone 能删除对应来源旧项。`GET /api/agent/v5/reports/{reportId}` 只允许当前有效 credential 读取当前注册/epoch 内的报告，返回 durable ack、Observation 状态与 Projection 状态。credential 被替换或撤销后，新报告和状态读取立即返回 401；替换前已提交的不可变报告仍可由后台恢复投递。

协议拒绝保留独立错误类别，不返回内部诊断或秘密。当前无已部署旧 Agent 的升级承诺；新注册须使用 V5，见 [运维](../deployment/operations.md)。企业任务签名、领取与启动许可见 [企业任务](enterprise-tasks.md)。

## 由原生 MDM 安装后首次注册

启用固定 Agent 安装策略后，安装器只获得公开的 installationOperation。Agent 自行生成并持久保存长期 credential 和 operationId，通过原生 MDM **实际客户端证书**在对应 Windows/Apple 管理 TLS 监听器调用 `POST /api/agent/v5/managed-registrations`：

```json
{
  "wireVersion": 5,
  "operationId": "非 nil UUID，重试保持不变",
  "installationOperation": "原生安装 Operation UUID",
  "credential": "Agent 自行生成的 43 字符无填充 Base64URL",
  "platform": "macos",
  "architecture": "aarch64",
  "capabilities": ["inventory.collect.v5", "mdm.enrollment.v5"]
}
```

证书链、当前有效 MDM 注册、安装下发记录、原始期限、取消、软件批准以及策略冻结的 SoftwareDeploy/Enrollment 授权都通过后，服务端在同一审计事务中创建并消费一次性 Enrollment，分配独立 Agent DeviceId，绑定凭据、能力及回执。公开 operationId、UDID、主机名和转发头均不构成身份。管理员退出会话不撤回已发布策略，实际权限撤销会阻止新注册。来源已退出 Scope 但安装已下发时，仍可在原期限内完成注册；禁用或更新策略不会延长旧操作授权。

首次成功返回 201；相同 operationId 与内容返回 200；更改内容或用另一 operationId 再消费同一安装返回 409。收到 operation_unknown 时重试原请求，不生成新 credential 或注册身份。已经提交的精确回执可以在原安装期限后恢复，但来源 MDM 和目标 Agent 注册必须仍有效。数据库不保存秘密明文；安装包不嵌入逐设备秘密。终端无法使用真实原生证书时，继续走上面的独立管理员 Enrollment 注册路径。

## Agent 上报本机 MDM 状态

具有 `mdm.enrollment.v5` 的 Agent 用 `/reports` 提交 `body:{"kind":"mdmEnrollment","state":"unenrolled"}`；其它闭合状态为 `this_organization`、`other_organization`、`unknown`。sequence 仍属于该 Agent 来源的单调报告序列。该事实进入现有 CollectionRun、Observation、Inventory，字段为 `channel.mdm.enrollment`。标准入口任务的结果只说明入口是否打开，完成注册须由后续本机观察证明。

## #2534 的 V3 → V4 无兼容退出决定

本次基线为 `1261f13`，V3 schema 指纹 `e4930817fec8a3032d9b3d144a4992c67bb45a89ffdecb0f08ca24e0ffbbc4c5`，V4 指纹 `925c5a7438f2a483fa280b5d5f8e26bcd451afa7d9a09c7a6129f37a155e40e0`。用户对 #2534 明确要求不向后兼容：V3 路由、schema、签名域和 capability 退出，所有 Agent 消费者须切换到 V4；不提供代理重写、双解码或旧执行许可。管理 HTTP API 的版本不随 Agent wire 一起变化。

V4 共 13 个网络 shape，新增 ManagedRegistrationRequest，并扩展通道观察和标准注册入口任务。当前数据库安装准入只接受空库或完整当前账本，不提供旧 Agent 注册数据的在线转换。固定签名 MSI/公证 PKG 及真实系统证书使用分别由 #2535/#2536 和 #2480/#2481 验证；本次受控协议样本不证明生产安装包或真机已可用。
