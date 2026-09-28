# Agent 注册与报告

服务端接入使用 [agent-wire](../../crates/agent-wire/README.md) 的闭合协议，版本、schema 和能力形态由协议包唯一持有。Agent 实现位于独立仓库；本指南不证明终端采集或执行已验收。

## 注册

管理员先按 [Enrollment 与审计](device-enrollment.md) 创建 `source: "agent.builtin"` 的授权，并把 enrollmentId 与一次性口令安全交给设备。Agent 自行生成另一个 32 字节随机值作为长期 credential，然后发送：

```json
{
  "wireVersion": 3,
  "operationId": "非 nil UUID",
  "enrollmentId": "管理员返回的 UUID",
  "password": "43 字符无填充 Base64URL",
  "credential": "另一个 43 字符无填充 Base64URL",
  "platform": "macos",
  "architecture": "aarch64",
  "capabilities": ["inventory.basic.v3"]
}
```

V3 capability 按顺序声明库存基础能力，以及脚本 `task.execute.v3`、软件 `software.execute.v3` 中实际支持的能力；后二者可单独或同时声明。仅库存注册访问任务返回 permission denied。平台和架构绑定在注册世代中，服务端据此选择精确任务变体，Agent 仍须用本机真实 OS/架构核验签名任务；声明本身不是受检硬件事实。V2 请求和路由不接受，不提供旧版解码或降级执行。

`POST /api/agent/v3/registrations` 仅接受 `Content-Type: application/json`，成功首次提交返回 201，精确重放返回 200；同 operationId 改变内容返回 409。绑定事务同时验证原管理员当前会话和 enrollment 权限、channel、口令版本、期限与世代，保存注册/来源/capability/成功审计并将 Enrollment 标为 bound。数据库只保存 tenant 域隔离的 SHA-256 locator，不保存 credential 明文。

同一设备再次完成 Agent 注册会建立下一世代并原子停用旧注册、旧 credential 和旧来源。MDM channel 世代相互独立。管理员撤销仍使用 `/api/v3/devices/{device}/registrations/{registration}/revoke` 和独立 `credentials` 权限。
## 报告与状态

报告请求使用严格的 `Authorization: Bearer <credential>`：

```json
{
  "wireVersion": 3,
  "reportId": "非 nil UUID",
  "sequence": 0,
  "observedAt": 1780000000,
  "body": {
    "kind": "snapshot",
    "values": [
      {"field": "device.model", "value": {"kind": "known", "value": "Model A"}},
      {"field": "device.os.version", "value": {"kind": "unsupported"}}
    ]
  }
}
```

V3 只接受 snapshot、partial、failed，不接受 delta。所有 UUID 使用小写 hyphenated 词法，`reportId` 在 tenant 内全局唯一；字段仅为 `device.model` 和 `device.os.version`；known 文本最多 256 个 Unicode 标量，snapshot/partial 中字段会规范排序，重复字段、未知字段、未知 JSON 成员和控制字符均拒绝。`POST /api/agent/v3/reports` 在不可变报告、摘要和成功审计提交后返回 202/durable；相同 reportId 与相同语义返回原 receivedAt，不同语义返回 409。

待投递报告达到有界容量时返回 service_unavailable，优先恢复既有 reportId。历史裁剪不得删除 pending 报告。Agent 与 Windows MDM 均由 `collection_runs` 持有不可变报告和最小交付进度，不存在第二套报告队列或 owner 分支。

恢复及 Agent 状态读取共同核对持久报告的 tenant、registration、source、epoch、dataset、reportId、sequence、coverage、规范字节和摘要，并要求报告已封存；数据库关系列与冻结报告内容不一致时拒绝恢复。

后台沿用唯一的 Inventory 运行时：持久报告恢复后提交 Observation，snapshot 可进入投影；partial/failed 形成 need-snapshot 决策而不投影。`GET /api/agent/v3/reports/{reportId}` 只允许当前有效 credential 读取当前注册/epoch 内的报告，返回 durable ack、Observation 状态与 Projection 状态。credential 被替换或撤销后，新报告和状态读取立即返回 401；替换前已提交的不可变报告仍可由后台恢复投递。

协议拒绝保留独立错误类别，不返回内部诊断或秘密。当前无已部署旧 Agent 的升级承诺；新注册须使用 V3，见 [运维](../deployment/operations.md)。企业任务签名、领取与启动许可见 [企业任务](enterprise-tasks.md)。

## #2470 的 V2 → V3 无兼容退出决定

本次破坏性替换绑定基线 commit `06bd46d65dfa9a04ecedd5a576c6b1e33c7b7e2b`，其 Agent V2 schema 指纹为 `d5c7e3cf7ab73c711d0eaca663c5bc622136b9f4b16453819f8d7a6138f7afc1`，新 V3 指纹为 `e4930817fec8a3032d9b3d144a4992c67bb45a89ffdecb0f08ca24e0ffbbc4c5`。用户为 #2470 明确选择不向后兼容，并在 PR #1126 再审批量确认本项在当前 PR 完成；基线或任一 schema 指纹漂移时，本段不自动授权其它破坏性变更。

精确 deny 清单：

- V2 的 `/api/agent/v2` 注册、报告、任务领取、事件、内容路径整体退出；V3 是新路径身份，不做代理重写或降级。
- `wireVersion:2`、V2 签名域与 `inventory.basic.v2` / `task.execute.v2` 能力退出；注册新增必需的平台与架构，软件任务新增独立能力。旧凭据不被解释成 V3 执行许可。
- 旧清单中的 RegistrationRequest、RegistrationReceipt、ReportRequest、ReportAck、ReportStatus、ErrorBody、TaskClaimRequest、TaskEventRequest、TaskPayload、SignedTask、TaskClaimResponse、TaskEventAck 共 12 个网络 shape 的 V2 schema ID 被 V3 ID 替换；旧 schema 和兼容基线脚本删除，不提供双版本反序列化。
- `mdm_access.agent_bindings` 的新安装准入仅接受 V3 并保存平台/架构；安装器的 `accepted_ledger` 只接受空库或完整当前账本，不把旧数据库在线迁移伪装为兼容路径。

消费核查：#2564 尚未接入生产 Agent 任务消费者；当前本地 `rss-mdm-agent`、`rss-web`、`rss-identity` 源码无 `/api/agent/v2`、`wireVersion:2` 或 V2 capability 引用。仓内 V2 路由与 schema 已无活跃挂载。此结论只绑定上述基线与本次 PR 的消费集，不推断未来安装或外部 Agent 状态。
