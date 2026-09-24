# 企业脚本、采集模板与任务

Resource.Script 持有唯一的不可变执行定义。管理入口为 `/api/v3/resources/{id}`；原 `/api/v1/resources` 已删除。Agent 仅使用 `/api/agent/v2`。本页描述服务端协议；真实 Windows/macOS runner 分别由 #2475/#2476 验收，不能把模拟 Agent T2 当作设备执行证明。

## 配置与内容

配置可选 `tasks` 对象；未配置时任务创建拒绝，不影响基础报告：

```json
{
  "tasks": {
    "directory": "/var/lib/rss-mdm/tasks",
    "private_key_file": "/run/secrets/task-signing.pk8",
    "key_id": "enterprise-2026-09",
    "trusted_keys": {"enterprise-2026-09": "<32-byte Ed25519 public key, unpadded base64url>"}
  }
}
```

directory 必须预先存在，服务按 tenant 创建内容目录。每个 tenant 目录的 `.upload.lock` 用独占文件锁串行化所有实例的启动清扫和上传；启动及每次上传前只删除名称精确为 `.upload-<canonical hyphenated UUID>` 的普通文件，不删除锁文件、非普通文件或近似名称。锁、扫描、删除、写入和目录同步失败均报 CommandStorage 并阻止启动或本次上传；已存在内容的长度或摘要不符报 CommandInvariant。密钥为 Ed25519 PKCS#8，按其他 secret 文件的权限要求部署；活动私钥必须匹配配置中的可信公钥。Agent 的公钥集合通过受信任部署提供，不能信任任务自行携带的 keyId 或公钥。签名覆盖 keyId、tenant/device/registration/generation、task/attempt、平台与架构、用途、期限、资源摘要、内容长度/hash、解释器、身份、参数和预算。消费方调用 `SignedTask::verify` 时提供本地身份及预期 task/attempt/permit。

Script definition 包含 `profile`（power_shell7、posix_sh、bash、osquery_info_v1）、`runAs`（system、logged_in_user）、`encoding: utf8`、参数 Schema 与 `bindings`、输出 Schema、`purpose`、timeoutSeconds/outputBytes/maxRows。参数仅支持字符串、整数、布尔，必须全部显式绑定；不拼接 shell 命令。Schema 采用有界闭合子集，拒绝引用、组合器、正则与未知关键字。

先创建 Resource、加入完整 version，再通过
`POST /api/v3/resources/{id}/content?version=v1&variant=default&platform=macos&architecture=aarch64`
上传原始字节，最后 activate。上传需 ResourceWrite，精确长度与 SHA-256 必须匹配声明，同一摘要不可覆盖。osquery_info_v1 的唯一内容为 `SELECT version FROM osquery_info;` 加一个 LF，且 system、无参数、单行输出。

## 计划和授权

`POST /api/v3/script-plans` 接受 operationId、resource/version、platform/architecture/variant、parameters、devices、schedule、runLifetimeSeconds。devices 是不超过 256 个设备的冻结集合；每次产生任务绑定当前注册和 generation。每台设备最多可关联 128 个未到期且启用的 registration/check_in 计划（含待审批计划），超额创建返回 409；停用旧计划后可释放额度。计划不可变、revision 固定为 1；变更需新建计划并重新审批。

作者对每台设备需要 ScriptExecute。另一主体调用 `/script-plans/{id}/approve`，需要对全部目标具有 ScriptApprove。独立审批者不能与作者相同；审批不会绕过当前权限。生产、领取、启动和下载重新检查授权规则及成员关系，并要求当前 Agent 注册显式声明 `task.execute.v2`。只有 `inventory.basic.v2` 的注册仍可报告库存，但不会成为任务目标，任务 HTTP 也返回 permission denied。读取需要 OperationRead。`GET /script-plans/{id}` 仅返回计划元数据；`/{id}/runs` 每页最多 20 条摘要，不含 output、stdout 或 stderr，非空 nextCursor 用 afterAt/afterId 继续读取；`/{id}/runs/{taskId}` 返回单次完整执行证据。`/cancel` 需要 OperationCancel。停用计划后未开始任务不再执行；已启动任务的取消只表明请求或停止确认，不能证明副作用已撤销。

schedule 包含 notBefore/until、jitterSeconds、可选 window、misfire（skip 或 coalesce_one），trigger 为 manual、once(at)、interval(anchor,seconds)、weekly(zone,weekday,minute)、registration 或 check_in(minimumSeconds)。IANA 时区、星期 1–7；DST gap 跳过、fold 取较早时刻。窗口不跨午夜。有效期最多 366 天、抖动最多 3600 秒；错过默认跳过，coalesce_one 只合并最新一次。设备离线不会删除已生成任务，任务期限内可领取。窗口结束同时约束任务 deadline、offer 和 Start permit，窗口结束后不能启动。定时生产容量满时把原 occurrence 坐标持久化为 `blocked_at`，不推进 `scan_at`；重启和后续 tick 优先重试它。成功、重复或按原 occurrence 的 misfire/window/until/deadline 规则跳过后，才清空阻塞坐标并将扫描游标推进到该坐标，下一 tick 再合并后续触发。手动审批容量满返回 409；registration/check_in 使用各自稳定身份在后续事件或轮询重试。窗口等待保留原 occurrence 身份；重启不会产生同坐标重复任务。

## Agent 状态与结果

1. `POST /api/agent/v2/tasks/claim`：wireVersion=2、operationId，返回至多一个签名 offer 及不超过 128 条的取消页。领取候选与取消页独立选择，每个 registration 的取消游标持久化并循环遍历。task=null 的轮询不写永久执行回执，重试可看到新状态；实际 offer 在有效且仍获授权期间精确重放。
2. 验签后按 task/attempt 下载 `/tasks/{taskId}/content?attempt={attemptId}`。支持单段 Range、ETag 和 If-Range；每次都检查当前凭据及任务权限。下载后再次核对长度/hash。
3. 向 `/tasks/{taskId}/events` 提交 received，再提交 start。事件包含 wireVersion、operationId、attemptId、event。只有独立签名的短期 Start permit 可以授权启动，offer 本身不能启动。
4. 返回 result（exitCode、quality、output、diagnostics）或 cancelled。diagnostics 固定包含 stdout、stderr、durationMs、executedAt、failure：stdout/stderr 各最多 16 KiB UTF-8 字节；durationMs 不超过 3,600,000；executedAt 是大于零的 Unix 秒；failure 仅允许 launch_failed、timed_out、cancelled、non_zero_exit、output_limit、capture_failed 或 null。每次重试保留相同 operationId 与内容。已开始而结果未知的任务不自动重新领取；迟到的同 attempt 证据可以解释 Unknown。

交付、执行和取消分别保存；运行退出成功也只记录执行证据，effect 始终 unverified，不产生设备状态命令的 Applied 或虚构 StateDigest。持久结果包含 exitCode、quality、schemaValid、output、diagnostics 和 trusted；单 run 详情按 OperationRead 返回完整结果，列表摘要删除 output 以及 diagnostics.stdout/stderr，只保留受限状态和时间/失败分类。结构化 output 最大 1 MiB，具体版本还可设更小预算。

采集模板是 collection purpose 加固定字段 JSON Pointer 映射，不另建模板版本体系。只允许 corporate_agent.version（字符串）、corporate_agent.healthy（布尔）、osquery.version（字符串），完整键名均以 `custom.` 开头。前两项来源 agent.script，第三项来源 agent.osquery。完整、exitCode=0、schema 与字段类型均有效且权限仍有效、未超过任务或运行超时且未取消时，通过 CollectionRun → Observation → Inventory 发布。部分、截断、失败和非法输出只增加质量证据，保留可信事实及 lastKnown 的原始来源时间。没有 TTL。


归档只能通过管理端 Resource 入口，任务、策略和软件发布的历史引用统一阻止归档。审批、取消和执行事件的审计包含 plan；执行事件 target 为 task，registrationId 可反查设备，同一 operationId 可关联执行回执。
