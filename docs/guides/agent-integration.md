# Agent 注册与报告

服务端接入使用 [agent-wire](../../crates/agent-wire/README.md) 的闭合协议，版本、schema 和能力形态由协议包唯一持有。Agent 实现位于独立仓库；本指南不证明终端采集或执行已验收。

## 注册

管理员先按 [Enrollment 与审计](device-enrollment.md) 创建 `source: "agent.builtin"` 的授权，并把 enrollmentId 与一次性口令安全交给设备。Agent 自行生成另一个 32 字节随机值作为长期 credential，然后发送：

```json
{
  "wireVersion": 2,
  "operationId": "非 nil UUID",
  "enrollmentId": "管理员返回的 UUID",
  "password": "43 字符无填充 Base64URL",
  "credential": "另一个 43 字符无填充 Base64URL",
  "capabilities": ["inventory.basic.v2"]
}
```

V2 capability 只允许两个有序集合：仅库存的 `["inventory.basic.v2"]`，或库存加企业任务的 `["inventory.basic.v2","task.execute.v2"]`。服务按请求原样持久化；两者均可提交基础库存报告，只有第二种可以通过任务 HTTP、事务内复核和生产目标选择。库存-only 注册访问任务返回 permission denied，也不会被静默升级为执行主体。

`POST /api/agent/v2/registrations` 仅接受 `Content-Type: application/json`，成功首次提交返回 201，精确重放返回 200；同 operationId 改变内容返回 409。绑定事务同时验证原管理员当前会话和 enrollment 权限、channel、口令版本、期限与世代，保存注册/来源/capability/成功审计并将 Enrollment 标为 bound。数据库只保存 tenant 域隔离的 SHA-256 locator，不保存 credential 明文。

同一设备再次完成 Agent 注册会建立下一世代并原子停用旧注册、旧 credential 和旧来源。MDM channel 世代相互独立。管理员撤销仍使用 `/api/v3/devices/{device}/registrations/{registration}/revoke` 和独立 `credentials` 权限。
## 报告与状态

报告请求使用严格的 `Authorization: Bearer <credential>`：

```json
{
  "wireVersion": 2,
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

V2 只接受 snapshot、partial、failed，不接受 delta。所有 UUID 使用小写 hyphenated 词法，`reportId` 在 tenant 内全局唯一；字段仅为 `device.model` 和 `device.os.version`；known 文本最多 256 个 Unicode 标量，snapshot/partial 中字段会规范排序，重复字段、未知字段、未知 JSON 成员和控制字符均拒绝。`POST /api/agent/v2/reports` 在不可变报告、摘要和成功审计提交后返回 202/durable；相同 reportId 与相同语义返回原 receivedAt，不同语义返回 409。

待投递报告达到有界容量时返回 service_unavailable，优先恢复既有 reportId。历史裁剪不得删除 pending 报告。Agent 与 Windows MDM 均由 `collection_runs` 持有不可变报告和最小交付进度，不存在第二套报告队列或 owner 分支。

恢复及 Agent 状态读取共同核对持久报告的 tenant、registration、source、epoch、dataset、reportId、sequence、coverage、规范字节和摘要，并要求报告已封存；数据库关系列与冻结报告内容不一致时拒绝恢复。

后台沿用唯一的 Inventory 运行时：持久报告恢复后提交 Observation，snapshot 可进入投影；partial/failed 形成 need-snapshot 决策而不投影。`GET /api/agent/v2/reports/{reportId}` 只允许当前有效 credential 读取当前注册/epoch 内的报告，返回 durable ack、Observation 状态与 Projection 状态。credential 被替换或撤销后，新报告和状态读取立即返回 401；替换前已提交的不可变报告仍可由后台恢复投递。

协议拒绝保留独立错误类别，不返回内部诊断或秘密。升级须排空旧报告、撤销旧凭据并重新授权，见 [运维](../deployment/operations.md)。企业任务签名、领取与启动许可见 [企业任务](enterprise-tasks.md)。
