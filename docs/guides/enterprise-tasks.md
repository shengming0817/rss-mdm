# 企业脚本、采集模板与任务

Resource.Script 和 Resource.Software 分别持有不可变执行定义。管理入口为 `/api/v3/resources/{id}`，Agent 使用 `/api/agent/v4` 的签名任务协议。本页描述服务端接线；生产 Agent 消费归 #2564，受控 PG/HTTP 测试不构成真机证明。

## 配置与内容

内容与任务签名分别配置；仅维护软件目录需要 `content`，脚本和软件任务都需要 `content` 与 `task_signing`：

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

密钥为 Ed25519 PKCS#8，按其他 secret 文件的权限要求部署；活动私钥必须匹配配置中的可信公钥。Agent 公钥集合通过受信任部署提供，不能信任任务自行携带的 keyId 或公钥。签名覆盖 keyId、tenant/device/registration/generation、task/attempt、平台与架构、用途、期限及精确资源输入；脚本包含解释器、参数和预算，软件包含定义、批准身份、安装意图与全部产物摘要。消费方调用 `SignedTask::verify` 时提供本地身份及预期 task/attempt/permit。

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
    "scope": "11111111-1111-1111-1111-111111111111",
    "action": {"resource": {"id": "script", "version": "v1", "platform": "macos", "architecture": "aarch64", "variant": "default"},"kind": "execution", "parameters": {}, "runLifetimeSeconds": 300}
  }
}
```

默认签入触发、每执行版本一次、没有结束时间。显式设备也通过 Scope 的直接设备来源表达。Scope 引用持续跟随当前结果；发布不复制永久目标名单，也不生成全体 Run。空目标分配有效，未来 Scope 成员自动获得资格。

脚本分配需要 PolicyWrite、ResourceRead、ScopeRead 与设备范围 ScriptExecute；软件分配使用独立的设备范围 SoftwareDeploy，并要求当前企业软件批准。发布受理后归组织持有，不再依赖发布者的登录会话。Agent 注册须声明对应的 `task.execute.v5` 或 `software.execute.v5`；领取、下载和启动均重新核对凭据、注册世代和当前分配。

`frequency` 为 `once_per_version`、`once_per_entry` 或 `every_trigger`。可选 `schedule` 包含 trigger、notBefore、until、jitterSeconds、window 和 misfire。trigger 支持 manual、once(at)、interval(anchor,seconds)、weekly(zone,weekday,minute)、registration、check_in(minimumSeconds)。`until` 可省略。misfire 为 `{"kind":"coalesce_one"}`（默认）或 `{"kind":"skip","maxLatenessSeconds":30}`；窗口可跨午夜，星期按开始日计算，DST gap 跳过、fold 取较早时刻。

`POST /api/v2/policies/{id}/reruns` 使用 `operationId`、当前 `expectedRevision`、`input:{"deadline":...}` 请求显式重执行；只保存一个有期限触发，设备签入时才受理。已启动而结果未知的脚本不自动重跑。关闭分配阻止新执行并请求取消既有任务，取消不证明副作用回滚。

`GET /api/v2/policies` 按 `after` UUID 分页；`/{id}` 返回定义、编辑 revision 和执行 version；`/{id}/devices` 按设备 `after` 分页返回当前分配资格、诊断及原生 Operation 关联。执行历史 `/{id}/runs` 用 afterAt/afterId 分页，摘要不含输出；`/{id}/runs/{taskId}` 返回完整执行证据并检查 OperationRead。

## 一次性远程操作

`POST /api/v2/remote-operations` 接受 `operationId`、Resource 绑定、`targets`、`deadline` 和 `action`。脚本动作是 `{"kind":"execute","parameters":{}}`，当前原生配置动作是 `{"kind":"apply_configuration"}`。不创建长期 Policy，也不接受触发器或频率。`targets` 使用 `{"kind":"devices","devices":["device-id"]}` 或 `{"kind":"scope","id":"scope-uuid"}`。Scope 输入在受理时固定结果引用；后续入组或退出不改变本次目标。交付受理绑定当前注册世代；后续重新注册会使旧交付取消，查询保留该子任务状态。需要向新世代再次执行时，提交新的显式远程操作。

一个持久分页任务受理目标，Agent Run 等待主动领取，MDM 子 Operation 进入已有原生队列。单设备缺少通道、能力或容量会留下阻断原因并继续后续设备；离线但已有有效注册的设备仍可在期限内领取。过期后不再产生新子项或发放 Start permit。

`GET /api/v2/remote-operations/{id}?after=<device>` 返回有界目标页、子执行身份和状态；`POST /{id}/cancel` 携带新的 `operationId` 请求取消。重试创建时使用原 operationId 和原正文，恢复首次快照。取消只撤销本次尚未完成的执行资格，不表示已发生的副作用被回滚。

## Agent 状态与结果

1. `POST /api/agent/v5/tasks/claim`：wireVersion=4、operationId，返回至多一个签名 offer 及有界取消页。领取候选与取消页独立选择，每个 registration 的取消游标持久化并循环遍历。task=null 的轮询不写永久执行回执，重试可看到新状态；实际 offer 在有效且仍获授权期间精确重放。
2. 验签后按 task/attempt 下载脚本 `/tasks/{taskId}/content?attempt={attemptId}`；软件按签名产物 key 下载 `/tasks/{taskId}/content?attempt={attemptId}&artifact={urlEncodedKey}`。支持单段 Range、ETag 和 If-Range；每次都检查当前凭据、企业批准及任务权限。客户端最终核对长度/hash。
3. 向 `/tasks/{taskId}/events` 提交 received，再提交 start。事件包含 wireVersion、operationId、attemptId、event。只有独立签名的短期 Start permit 可以授权启动，offer 本身不能启动。
4. 返回 result（exitCode、quality、output、diagnostics）或 cancelled。diagnostics 的完整字段、闭合分类和预算见 [wire schema](../../crates/agent-wire/schema)。每次重试保留相同 operationId 与内容。已开始而结果未知的任务不自动重新领取；迟到的同 attempt 证据可以解释 Unknown。

交付、执行和取消分别保存；脚本运行退出成功只记录执行证据，脚本 effect 始终 unverified，不产生设备状态命令的 Applied 或虚构 StateDigest。脚本持久结果包含 exitCode、quality、schemaValid、output、diagnostics 和 trusted；单 run 详情按 OperationRead 返回完整结果，列表摘要删除 output 以及 diagnostics.stdout/stderr，只保留受限状态和时间/失败分类。结构化 output 同时遵守 wire 与资源版本预算。

采集模板是 collection purpose 加固定字段 JSON Pointer 映射，不另建模板版本体系。只允许 corporate_agent.version（字符串）、corporate_agent.healthy（布尔）、osquery.version（字符串），完整键名均以 `custom.` 开头。前两项来源 agent.script，第三项来源 agent.osquery。完整、exitCode=0、schema 与字段类型均有效且权限仍有效、未超过任务或运行超时且未取消时，通过 CollectionRun → Observation → Inventory 发布。部分、截断、失败和非法输出只增加质量证据，保留可信事实及 lastKnown 的原始来源时间。没有 TTL。


归档只能通过管理端 Resource 入口，任务、策略和软件发布的历史引用统一阻止归档。发布、取消和执行事件的审计保留策略或执行版本关联；执行事件 target 为 task，registrationId 可反查设备，同一 operationId 可关联执行回执。

### 一次性结果与恢复阶段

`GET /api/v2/remote-operations/{id}` 的结果摘要省略 output/stdout/stderr；`GET /api/v2/remote-operations/{id}/runs/{task}` 按设备 OperationRead 权限读取完整、已有预算约束的结果与诊断。Policy 与 Remote 使用同一 Run 结果过滤与详情投影。

`cancellationRequested` 与 `deadlineElapsed` 是意图/时间事实。仍有工作时，phase 为 preparing、dispatched、cancelling 或 expiring；全部工作收敛后为 completed，存在无法确认的执行则为 unknown。completed 表示处理收敛，不表示每个设备执行成功，更不证明脚本效果回滚；各设备结果仍独立展示。取消返回 cancellationRequested，不把写入取消意图称为设备取消完成。

服务端的软件变体选择使用当前 Agent 注册声明的平台和架构，终端必须再用本机真实 OS/架构核验签名任务。注册声明不等于受检硬件事实；统一 applicability 的受检事实仍由 [PBI #2572](https://dev.azure.com/shengming0923/rss/_workitems/edit/2572) 跟踪。

## 软件分配与灰度

同一软件 Policy 用 `resource:{kind:"software",id,version,variants}` 将每个支持的平台/架构映射到精确变体。`action.kind:"software"` 的 `intent` 为 `required_install`、`available_install` 或 `explicit_uninstall`；后者要求软件定义声明卸载。`admissionOperation` 必须是当前企业软件版本批准的 operation；撤销后重新批准，需要管理员以新 operation 更新 Policy，生成新的执行版本，旧版本不会自动复活。管理员在 `rollout.stages` 中按顺序指定 Scope 与 UTC Unix `opensAt`，可选 `minimumVerifiedPercent` 仅约束前一阶段；未设置时到时间自动开放。`disable` 暂停新任务，`enable` 恢复；仅编辑范围和时间不产生新的软件执行版本。动态 Scope 决定后续准入，既有 Run 与核实证据保持原身份。

Agent 只收到单次可执行任务，不消费 Policy、Scope、灰度、Catalog 身份或企业批准 operation。后端在发布分配时验证固定依赖可在目标平台解析，并在签发时按依赖优先顺序生成 `steps`；每一步是闭合的本机动作、检测规则、任务产物与必要的包管理器 export identity。任务不携带依赖图或来源准入模型。`definitionDigest` 绑定完整步骤序列；内容键为 `{步骤下标}/{该步骤产物键}`，下载时作为 URL 编码的 `artifact` 查询参数。`startMode:user_initiated` 表示可选任务须经可信本地用户操作后才能请求 Start，`automatic` 表示可自动开始。Offer 仅用于准备和下载，过期后不能继续取内容；Start permit 才能执行。软件分配使用执行版本下稳定的期望身份；核实成功后不因签入重复安装，明确失败总共至多三次尝试并逐次退避，未启动的自选 Offer 到期后可以重新领取。Agent 软件计划决定本机安装动作并做独立检测；服务端分别保存 installer exit、检测状态、版本与证据摘要。核实成功、明确失败、等待重启、未知效果分开记录；未知或等待重启不盲目重试，设备重新注册也不解除未知阻断。来源 Published、下载成功、exit 0 和任务回执均不能替代核实成功。

`GET /api/v2/policies/{id}/software/rollout` 返回每阶段当前总目标、已回报、等待用户、未知、等待重启、明确失败、核实成功和无可用软件能力设备数，以及暂停、时间与可选门槛。自选任务被领取且尚未启动、Offer 仍有效时，逐 Run 的 `userAction` 与灰度统计显示 `waiting_user`。阶段历史按稳定 Scope 身份归属，重排阶段不会复用其他 Scope 的结果。Policy 预览和设备页另外返回服务端计算的闭合 `taskAdmission` 原因，不把单纯 Scope 命中称为可执行。读取要求 PolicyRead 与全设备 OperationRead；这些是当前动态目标的统计，历史任务证据不被重算。真实设备身份、可信用户交互和软件执行适配由 #2564 消费本协议，平台 T3 由 #2480/#2481 验收。

## 通道接入策略

MDM 与 Agent 各自持有 DeviceId、注册世代、凭据、采集和策略。MDM 来源字段 `channel.agent.installation` 的 `absent` 才能触发安装；Agent 来源 `channel.mdm.enrollment` 的 `unenrolled` 才能触发标准入口。可以将这些字段用于动态 Group，再通过 Scope 分配策略。当前有效来源的最新完整观察是依据，没有 TTL 或最后连接时间门槛；未知、失败、第三方 MDM 和旧注册观察不会变成缺失。

`action:{kind:"ensure_agent_installed",resource:{kind:"software",id,version,variants},admissionOperation,runLifetimeSeconds}` 仅引用当前批准的固定 Agent 软件。发布需要覆盖未来成员的全设备 SoftwareDeploy 与 Enrollment 授权；它们随策略冻结，后续执行仍核对实际权限。Windows 采用固定 ProductID 的 Add/Exec；macOS 采用固定 PKG Manifest。版本、SHA-256、发布身份、无自定义参数和无依赖均需匹配部署 pin。已有 Agent 不自动升级，Scope 退出阻止尚未派发的新安装；已派发安装可在原期限内完成独立 Agent 注册，但当前策略版本、实际权限、软件批准和来源世代仍须有效。Scope 退出不卸载 Agent。重叠策略和重复报告共享来源注册下的一次安装；结果未知先继续查询，不重新运行安装器。单个操作仍受原始期限、取消及普通命令容量限制。

安装配置默认关闭。部署 `agent_installation`：`content_origin` 为公开 HTTPS 内容服务根地址；`packages` 按 `windows_x86_64`、`windows_aarch64`、`macos_x86_64`、`macos_aarch64` 选择实际发布组合，每项包含 `identity`、`package`、`version`、`sha256`（32 个字节的 JSON 数组）。Windows identity 为 `{platform:"windows",product:"ProductID UUID",publisher:"签名发布者"}`；macOS 为 `{platform:"macos",receipt:"PKG receipt",bundle:"Agent bundle ID",team:"10 字符 Team ID"}`。这些值必须与普通 Software 目录中审核、上传、激活和批准的 release 相同。同平台不同架构必须使用同一产品身份。

Apple 新注册 profile 在启用该能力时申请已安装应用查询与企业应用安装 AccessRights；既有 profile 不会因服务器配置更新获得权限，需通过正常注册流程更新。采集要求 macOS 12+ 的明确 IsAppleSilicon 结果；Windows 只对明确的 64 位架构证据选择包。固定内容下载只暴露批准的包，不承载秘密，并复用单段 Range/ETag 和撤销检查。应分别读取操作中的原生 delivery、installation、独立 agentRegistration 与 capabilities；Acknowledged 不能证明安装完成。macOS 的 InstalledApplicationList 只证明同 bundle/version 的应用存在，不能核实签名 Team ID 或 PKG receipt，因此采集、策略诊断及原生 installation 均保持 unknown，不判 already_satisfied，也不据此重装。独立 Agent 注册及能力仍单独显示；配置中的 receipt/team 是批准产物的身份约束，不是设备侧签名证明。

`action:{kind:"request_mdm_enrollment",organization:"本租户 UUID",runLifetimeSeconds}` 使用部署 `enrollment_entries:{windows:"https://发现服务域名",macos:"https://注册页面"}`，需要全设备 Enrollment 权限和 Agent 的 `mdm.enrollment.v5` 能力。任务有签名 Offer/Start permit，Windows 打开标准注册 UI，macOS 打开 HTTPS 注册页面，保留系统、账户和用户确认。`enrollment_result` 的 `opened`、`user_required`、`third_party_conflict`、`unsupported`、`failed`、`unknown` 分开保存；取消使用独立的 `{kind:"cancelled"}` 事件。opened 不证明 MDM 已注册。自动触发在同一 Agent 注册下去重；未知执行阻止重试，管理员显式 rerun 仍受当前权限、观察、期限和取消约束。

两种动作分别配置与启停，不依赖另一通道先完成，也不使用跨通道设备关联。物理设备关联由 #2578 持有；生产 Agent 和安装包由独立客户端任务消费本契约。
