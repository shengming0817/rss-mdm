# 企业脚本、采集模板与任务

Resource.Script 持有唯一的不可变执行定义。管理入口为 `/api/v3/resources/{id}`；原 `/api/v1/resources` 已删除。Agent 仅使用 `/api/agent/v2`。本页描述服务端协议；真实 Windows/macOS runner 分别由 #2475/#2476 验收，不能把模拟 Agent T2 当作设备执行证明。

## 配置与内容

内容与任务签名分别配置；软件目录只需要 `content`，脚本任务需要同时配置 `content` 和 `task_signing`。旧 `tasks` 配置已删除：

```json
{
  "content": {
    "directory": "/var/lib/rss-mdm/content",
    "imports": {},
    "max_artifact_bytes": 8589934592,
    "max_temporary_bytes": 34359738368,
    "max_uploads": 4,
    "transfer_seconds": 1800,
    "retention_seconds": 86400,
    "max_bundle_bytes": 17179869184,
    "max_bundle_entries": 4096,
    "max_expansion_ratio": 100
  },
  "task_signing": {
    "private_key_file": "/run/secrets/task-signing.pk8",
    "key_id": "enterprise-2026-09",
    "trusted_keys": {"enterprise-2026-09": "<32-byte Ed25519 public key, unpadded base64url>"}
  }
}
```

`directory` 必须预先存在，服务按 tenant 隔离内容和上传会话。数据以 SHA-256 寻址；临时文件长度/hash 全部核对后才原子发布。正文按固定缓冲流式读写，脚本自身仍限制为 16MiB。`max_uploads` 限定占用临时空间的上传会话数量，并作为全进程共享的内容校验/传输并发上限；配额不足拒绝，不建立无界等待队列。`transfer_seconds` 限制传输预算，`retention_seconds` 限制上传恢复窗口。单个软件产物硬上限为 1TiB，实际部署必须显式选择更小或相等的预算；网关正文上限与之配套。

同一上传 ID 的元数据持久化已确认 offset；未确认文件尾部在续传时截断。过期会话在新上传或显式清理时回收。原子落盘后数据库事务失败可能留下未引用文件；`POST /api/v3/software/content/cleanup` 需要 ResourceWrite，每轮至多清理 128 个超过保留窗口且无有效引用、无活跃读写的对象。清理查询 ResourceStore 的全部产物引用索引，包括复用已有摘要但未重新上传的资源。归档不抹去批准、发布或执行证据；仍被引用的内容不会清理。跨进程 blob 锁使用固定 256 个摘要分片，锁文件不随制品数量增长；不同摘要落入同一分片时，互斥写入可能返回冲突，清理会略过被占用的分片，稍后重试。不得手工删除 `.upload-*`、`.blob-lock-*` 或正在使用的内容文件。

密钥为 Ed25519 PKCS#8，按其他 secret 文件的权限要求部署；活动私钥必须匹配配置中的可信公钥。Agent 公钥集合通过受信任部署提供，不能信任任务自行携带的 keyId 或公钥。签名覆盖 keyId、tenant/device/registration/generation、task/attempt、平台与架构、用途、期限、资源摘要、内容长度/hash、解释器、身份、参数和预算。消费方调用 `SignedTask::verify` 时提供本地身份及预期 task/attempt/permit。

Script definition 包含 `profile`（power_shell7、posix_sh、bash、osquery_info_v1）、`runAs`（system、logged_in_user）、`encoding: utf8`、参数 Schema 与 `bindings`、输出 Schema、`purpose`、timeoutSeconds/outputBytes/maxRows。参数仅支持字符串、整数、布尔，必须全部显式绑定；不拼接 shell 命令。Schema 采用有界闭合子集，拒绝引用、组合器、正则与未知关键字。

先创建 Resource、加入完整 version，再使用固定 operation UUID 通过
`POST /api/v3/resources/{id}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation=<UUID>`
上传原始字节，最后 activate。上传需 ResourceWrite，精确长度与 SHA-256 必须匹配声明，同一摘要不可覆盖。osquery_info_v1 的唯一内容为 `SELECT version FROM osquery_info;` 加一个 LF，且 system、无参数、单行输出。

## Policy 分配与权限

在 `POST /api/v2/policies/{id}` 发送 `operationId`、`expectedRevision` 和 `input`。`input.action` 为 `put`、`enable` 或 `disable`。执行型定义示例：

```json
{
  "action": "put",
  "enabled": true,
  "definition": {
    "resource": {"id": "script", "version": "v1", "platform": "macos", "architecture": "aarch64", "variant": "default"},
    "scope": "11111111-1111-1111-1111-111111111111",
    "behavior": {"kind": "execution", "parameters": {}, "runLifetimeSeconds": 300}
  }
}
```

默认签入触发、每执行版本一次、没有结束时间。显式设备也通过 Scope 的直接设备来源表达。Scope 引用持续跟随当前结果；发布不复制永久目标名单，也不生成全体 Run。空目标分配有效，未来 Scope 成员自动获得资格。

管理需要 PolicyWrite，以及目标的 ScriptExecute；Scope 分配另需 ScopeRead 和全设备 ScriptExecute。发布受理后归组织持有，不再依赖发布者的登录会话、岗位或授权规则。没有 ScriptPlan 保存或强制第二人审批步骤。Agent 注册仍须声明 `task.execute.v2`，领取、下载和启动仍验证凭据、设备世代和当前分配。

`frequency` 为 `once_per_version`、`once_per_entry` 或 `every_trigger`。可选 `schedule` 包含 trigger、notBefore、until、jitterSeconds、window 和 misfire。trigger 支持 manual、once(at)、interval(anchor,seconds)、weekly(zone,weekday,minute)、registration、check_in(minimumSeconds)。`until` 可省略。misfire 为 `{"kind":"coalesce_one"}`（默认）或 `{"kind":"skip","maxLatenessSeconds":30}`；窗口可跨午夜，星期按开始日计算，DST gap 跳过、fold 取较早时刻。

`POST /api/v2/policies/{id}/reruns` 使用 `operationId`、当前 `expectedRevision`、`input:{"deadline":...}` 请求显式重执行；只保存一个有期限触发，设备签入时才受理。已启动而结果未知的脚本不自动重跑。关闭分配阻止新执行并请求取消既有任务，取消不证明副作用回滚。

`GET /api/v2/policies` 按 `after` UUID 分页；`/{id}` 返回定义、编辑 revision 和执行 version；`/{id}/devices` 按设备 `after` 分页返回当前分配资格、诊断及原生 Operation 关联。执行历史 `/{id}/runs` 用 afterAt/afterId 分页，摘要不含输出；`/{id}/runs/{taskId}` 返回完整执行证据并检查 OperationRead。

## 一次性远程操作

`POST /api/v2/remote-operations` 接受 `operationId`、Resource 绑定、`targets`、`deadline` 和 `action`。脚本动作是 `{"kind":"execute","parameters":{}}`，当前原生配置动作是 `{"kind":"apply_configuration"}`。不创建长期 Policy，也不接受触发器或频率。`targets` 使用 `{"kind":"devices","devices":["device-id"]}` 或 `{"kind":"scope","id":"scope-uuid"}`。Scope 输入在受理时固定结果引用；后续入组或退出不改变本次目标。交付受理绑定当前注册世代；后续重新注册会使旧交付取消，查询保留该子任务状态。需要向新世代再次执行时，提交新的显式远程操作。

一个持久分页任务受理目标，Agent Run 等待主动领取，MDM 子 Operation 进入已有原生队列。单设备缺少通道、能力或容量会留下阻断原因并继续后续设备；离线但已有有效注册的设备仍可在期限内领取。过期后不再产生新子项或发放 Start permit。

`GET /api/v2/remote-operations/{id}?after=<device>` 返回有界目标页、子执行身份和状态；`POST /{id}/cancel` 携带新的 `operationId` 请求取消。重试创建时使用原 operationId 和原正文，恢复首次快照。取消只撤销本次尚未完成的执行资格，不表示已发生的副作用被回滚。

## Agent 状态与结果

1. `POST /api/agent/v2/tasks/claim`：wireVersion=2、operationId，返回至多一个签名 offer 及有界取消页。领取候选与取消页独立选择，每个 registration 的取消游标持久化并循环遍历。task=null 的轮询不写永久执行回执，重试可看到新状态；实际 offer 在有效且仍获授权期间精确重放。
2. 验签后按 task/attempt 下载 `/tasks/{taskId}/content?attempt={attemptId}`。支持单段 Range、ETag 和 If-Range；每次都检查当前凭据及任务权限。下载后再次核对长度/hash。
3. 向 `/tasks/{taskId}/events` 提交 received，再提交 start。事件包含 wireVersion、operationId、attemptId、event。只有独立签名的短期 Start permit 可以授权启动，offer 本身不能启动。
4. 返回 result（exitCode、quality、output、diagnostics）或 cancelled。diagnostics 的完整字段、闭合分类和预算见 [wire schema](../../crates/agent-wire/schema)。每次重试保留相同 operationId 与内容。已开始而结果未知的任务不自动重新领取；迟到的同 attempt 证据可以解释 Unknown。

交付、执行和取消分别保存；运行退出成功也只记录执行证据，effect 始终 unverified，不产生设备状态命令的 Applied 或虚构 StateDigest。持久结果包含 exitCode、quality、schemaValid、output、diagnostics 和 trusted；单 run 详情按 OperationRead 返回完整结果，列表摘要删除 output 以及 diagnostics.stdout/stderr，只保留受限状态和时间/失败分类。结构化 output 同时遵守 wire 与资源版本预算。

采集模板是 collection purpose 加固定字段 JSON Pointer 映射，不另建模板版本体系。只允许 corporate_agent.version（字符串）、corporate_agent.healthy（布尔）、osquery.version（字符串），完整键名均以 `custom.` 开头。前两项来源 agent.script，第三项来源 agent.osquery。完整、exitCode=0、schema 与字段类型均有效且权限仍有效、未超过任务或运行超时且未取消时，通过 CollectionRun → Observation → Inventory 发布。部分、截断、失败和非法输出只增加质量证据，保留可信事实及 lastKnown 的原始来源时间。没有 TTL。


归档只能通过管理端 Resource 入口，任务、策略和软件发布的历史引用统一阻止归档。发布、取消和执行事件的审计保留策略或执行版本关联；执行事件 target 为 task，registrationId 可反查设备，同一 operationId 可关联执行回执。
