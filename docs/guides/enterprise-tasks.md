# 企业脚本、采集模板与任务

Resource.Script 和 Resource.Software 分别持有不可变执行定义。管理入口为 `/api/v1/resources/{id}`，Agent 使用 `/api/v1/agent/runtime` 的签名任务协议。本页描述服务端接线；生产 Agent 消费归 #2564，受控 PG/HTTP 测试不构成真机证明。

## 配置与内容

内容与任务签名分别配置；仅维护软件目录需要 `content`，Agent 脚本和软件任务需要 `content` 与 `task_signing`，原生 MDM 软件只使用 `content` 及既有原生通道凭据：

```json
{
  "content": {
    "storage": {"kind": "volume", "directory": "/var/lib/rss-mdm/content"},
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
    "revision": 1
  }
}
```

`storage` 必须显式选择后端；卷模式的 `directory` 必须预先存在。内容以逻辑 SHA-256 和长度寻址，物理对象使用独立不可变身份，由 PostgreSQL 清单绑定。脚本与原生配置自身仍限制为 16MiB。`max_uploads` 限定活跃上传数量，并作为当前实例内容校验/传输并发上限；临时额度由 PostgreSQL 在同租户多实例间共享，配额不足拒绝，不建立无界等待队列。`transfer_seconds` 限制单次内容操作的绝对总预算，覆盖资源检查、传输、校验、完成及绑定提交；各阶段共享截止时间，其中预留 `min(6秒, 总预算/4)` 用于结算和清理。流式上传与完成操作由内容服务持有此预算，普通管理请求维持 8 秒预算。取消后的清理只释放匹配 epoch 的租约，未确认的释放由持久化期限和恢复机制处理，不表示业务回滚成功，`retention_seconds` 限制上传恢复窗口。单个软件产物硬上限为 1TiB，实际部署必须显式选择更小或相等的预算；网关正文上限与之配套。

同一 actor/上传 ID 的元数据由 PostgreSQL 持久化已确认 offset。续传从已确认清单恢复，未确认对象由登记意图保留并参与额度计算；多实例的 epoch 防止旧写者推进新 frontier。`POST /api/v1/software/content/cleanup` 需要 ResourceWrite，每轮有界检查过期且无有效引用、无活跃读写的候选。清理查询 ResourceStore 的全部产物引用索引，包括复用已有摘要但未重新上传的资源。归档不抹去批准、发布或执行证据；仍被引用的内容不会清理。删除屏障与新 Resource 引用串行，S3/卷 I/O 在事务外执行。不得手工删除内容控制状态或正在使用的物理对象。

密钥为 Ed25519 PKCS#8，按其他 secret 文件的权限要求部署；活动私钥必须匹配配置中的可信公钥。Agent 公钥集合通过受信任部署提供，不能信任任务自行携带的 keyId 或公钥。签名覆盖 keyId、tenant/device/registration/generation、task/attempt、平台与架构、用途、期限及精确资源输入；脚本包含解释器、参数和预算，软件包含定义、生命周期绑定、安装意图与全部产物摘要。消费方调用 `SignedTask::verify` 时提供本地身份及预期 task/attempt/permit。

Script definition 包含 `profile`（power_shell7、posix_sh、bash、osquery）、`runAs`（system、logged_in_user）、`encoding: utf8`、参数 Schema 与 `bindings`、输出 Schema、`purpose`、timeoutSeconds/outputBytes/maxRows。参数仅支持字符串、整数、布尔，必须显式提供。脚本使用 bindings，SQL 模板使用 sql 中声明的命名参数并保持 bindings 为空；参数作为字面量绑定，不拼接 shell 命令或 SQL 语法。Schema 采用有界闭合子集，拒绝引用、组合器、正则与未知关键字。

先创建 Resource、加入完整 version，再使用固定 operation UUID 通过
`POST /api/v1/resources/{id}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation=<UUID>`
上传原始字节，最后 activate。上传需 ResourceWrite，精确长度与 SHA-256 必须匹配声明，同一摘要不可覆盖。osquery 模板的内容是与声明 sql 完全一致的 UTF-8 SQL 字节，固定版本、摘要和合法参数；仅允许受控 SELECT、表/列/函数及平台，必须使用 system 和 collection purpose。`SELECT version FROM osquery_info` 是普通模板示例，可通过 `/0/version` 映射字段；输出为空与失败分别表达。服务端和 Agent 共同消费 SQL 校验与参数绑定规则，周期采集和按需刷新只引用已发布版本，不接受临时 SQL。

## Policy 分配与权限

在 `POST /api/v1/policies/{id}` 发送 `operationId`、`expectedRevision` 和 `input`。`input.action` 为 `put`、`enable` 或 `disable`。执行型定义示例：

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

脚本分配需要 PolicyWrite、ResourceRead、ScopeRead 与设备范围 ScriptExecute；软件分配使用独立的设备范围 SoftwareDeploy，并要求当前企业软件生命周期有效。发布受理后归组织持有，不再依赖发布者的登录会话。Agent 注册须声明对应的 `task.execute.v1` 或 对应软件格式/作用域 profile；领取、下载和启动均重新核对凭据、注册世代和当前分配。

`frequency` 为 `once_per_version`、`once_per_entry` 或 `every_trigger`。可选 `schedule` 包含 trigger、notBefore、until、jitterSeconds、window 和 misfire。trigger 支持 manual、once(at)、interval(anchor,seconds)、weekly(zone,weekday,minute)、registration、check_in(minimumSeconds)。`until` 可省略。misfire 为 `{"kind":"coalesce_one"}`（默认）或 `{"kind":"skip","maxLatenessSeconds":30}`；窗口可跨午夜，星期按开始日计算，DST gap 跳过、fold 取较早时刻。

`POST /api/v1/policies/{id}/reruns` 使用 `operationId`、当前 `expectedRevision`、`input:{"deadline":...}` 请求显式重执行；只保存一个有期限触发，设备签入时才受理。此入口用于支持显式重执行的脚本与运维动作；标准 native_collection/agent_collection 只按固定周期执行，不接受 rerun。已启动而结果未知的脚本不自动重跑。关闭分配阻止新执行并请求取消既有任务，取消不证明副作用回滚。

`GET /api/v1/policies` 按 `after` UUID 分页；`/{id}` 返回定义、编辑 revision 和执行 version；`/{id}/devices` 按设备 `after` 分页返回当前分配资格、诊断及原生 Operation 关联。执行历史 `/{id}/runs` 用 afterAt/afterId 分页，摘要不含输出；`/{id}/runs/{taskId}` 返回完整执行证据并检查 OperationRead；采集结果另需 InventoryRead，冻结映射含敏感字段时还需 InventorySensitiveRead。

## 设备动作与退出边界

[#2623](https://dev.azure.com/shengming0923/rss/_workitems/edit/2623) 已退出 Remote 创建和资源分发：`POST /api/v1/remote-operations` 不再存在，不保留 execute、collect_native、apply_configuration 或软件动作，也不转换成临时 Policy。脚本、原生采集、配置和软件由各自的 Resource/Policy/Scope 生命周期提供。

#2755 已确认不存在旧 Remote / 通用 direct 部署与升级义务，历史读取、撤销、结算、存储和诊断下载链路完整退出。不改写旧记录或转换为 Policy；旧安装账本不属于当前 fresh install 支持范围。

设备创建只有 restart、lock、wipe，严格动作参数、确认、平台注册前提和权限见[设备操作](device-operations.md)。资源级配置与软件不借用设备动作入口。

## Agent 状态与结果

1. `POST /api/v1/agent/runtime/tasks/claim`：wireVersion=1、operationId、当前 profiles 和 executionContext，返回至多一个签名 offer 及有界取消页。领取候选与取消页独立选择，每个 registration 的取消游标持久化并循环遍历。task=null 的轮询不写永久执行回执，重试可看到新状态；实际 offer 在有效且仍获授权期间精确重放。
2. 验签后按 task/attempt 下载脚本 `/tasks/{taskId}/content?attempt={attemptId}`；软件按签名产物 key 下载 `/tasks/{taskId}/content?attempt={attemptId}&artifact={urlEncodedKey}`。支持单段 Range、ETag 和 If-Range；每次都检查当前凭据、软件生命周期及任务权限。客户端最终核对长度/hash。
3. 向 `/tasks/{taskId}/events` 提交 received，再提交 start。事件包含 wireVersion=1、operationId、attemptId、event、executionContext。只有独立签名的短期 Start permit 可以授权启动，offer 本身不能启动。
4. 返回 result（exitCode、quality、output、diagnostics、collectedAt）或 cancelled。diagnostics 的完整字段、闭合分类和预算见 [wire schema](../../crates/agent-wire/schema)。每次重试保留相同 operationId 与内容。已开始而结果未知的任务不自动重新领取；迟到的同 attempt 证据可以解释 Unknown。

交付、执行和取消分别保存；脚本运行退出成功只记录执行证据，脚本 effect 始终 unverified，不产生设备状态命令的 Applied 或虚构 StateDigest。脚本持久结果包含 exitCode、quality、schemaValid、output、diagnostics、trusted、Agent 原生 collectedAt 与服务端 receivedAt；单 run 详情检查设备 OperationRead；采集结果另查 InventoryRead，含敏感字段再查 InventorySensitiveRead，随后才返回原始 output 与 stdout/stderr。列表摘要删除 output 以及 diagnostics.stdout/stderr，只保留受限状态和时间/失败分类。结构化 output 同时遵守 wire 与资源版本预算。

采集模板使用 collection purpose 和字段键→JSON Pointer 映射，不另建版本体系。映射引用统一版本化目录中的内置或自定义字段，按字段类型、平台、来源与敏感级别冻结；不再限制为三个固定字段。脚本与 SQL 分别使用 agent.script 与 agent.osquery。预算合法、exitCode=0、输出完整且执行仍可信时，字段独立校验后经 CollectionRun→Observation→Inventory 发布；缺失或无效字段可形成部分结果，合法字段仍可更新。失败、截断、超预算和不可信结果不清空历史可信事实；来源冲突与完整快照/tombstone 删除按统一选值规则处理，不引入 TTL。


归档只能通过管理端 Resource 入口，任务、策略和软件发布的历史引用统一阻止归档。发布、取消和执行事件的审计保留策略或执行版本关联；执行事件 target 为 task，registrationId 可反查设备，同一 operationId 可关联执行回执。

服务端的软件变体选择使用当前 Agent 注册声明的平台和架构，终端必须再用本机真实 OS/架构核验签名任务。注册声明不等于受检硬件事实；统一 applicability 的受检事实仍由 [PBI #2572](https://dev.azure.com/shengming0923/rss/_workitems/edit/2572) 跟踪。

## 软件分配与灰度

同一软件 Policy 用 `resource:{kind:"software",id,version,variants}` 将每个支持的平台/架构映射到精确变体。`action.kind:"software"` 的 `intent` 为 `required_install`、`available_install` 或 `explicit_uninstall`；后者要求软件定义声明卸载。Policy 不接受 `admissionOperation`；后台冻结当前来源、版本和依赖的生命周期绑定。撤回后重新启用，需要管理员重新提交 Policy，生成新的执行版本，旧版本不会自动复活。管理员在 `rollout.stages` 中按顺序指定 Scope 与 UTC Unix `opensAt`，可选 `minimumVerifiedPercent` 仅约束前一阶段；未设置时到时间自动开放。`disable` 暂停新任务，`enable` 恢复；仅编辑范围和时间不产生新的软件执行版本。动态 Scope 决定后续准入，既有 Run 与核实证据保持原身份。

Agent 只收到单次可执行任务与服务端授权坐标，不消费 Policy 定义、Scope、灰度或企业批准模型。后端在发布分配时验证固定依赖可在目标平台解析，并在签发时按依赖优先顺序生成 `steps`；每一步是闭合的本机动作、检测规则、任务产物与必要的包管理器 export identity。任务不携带依赖图或来源准入模型。`definitionDigest` 绑定完整步骤序列；内容键为 `{步骤下标}/{该步骤产物键}`，下载时作为 URL 编码的 `artifact` 查询参数。`startMode:user_initiated` 表示可选任务须经可信本地用户操作后才能请求 Start；显式自助请求的交互可提供该确认，不要求重复点击。`automatic` 表示后台任务可自动开始。Offer 仅用于准备和下载，过期后不能继续取内容；Start permit 才能执行。软件分配使用执行版本下稳定的期望身份；核实成功后不因签入重复安装，明确失败总共至多三次尝试并逐次退避，未启动的自选 Offer 到期后可以重新领取。Agent 软件计划决定本机安装动作并做独立检测；服务端分别保存 installer exit、检测状态、版本与证据摘要。核实成功、明确失败、等待重启、未知效果分开记录；未知或等待重启不盲目重试，设备重新注册也不解除未知阻断。来源 Published、下载成功、exit 0 和任务回执均不能替代核实成功。

`GET /api/v1/policies/{id}/software/rollout` 返回每阶段当前总目标、已回报、等待用户、未知、等待重启、明确失败、核实成功和无可用软件能力设备数，以及暂停、时间与可选门槛。自选任务被领取且尚未启动、Offer 仍有效时，逐 Run 的 `userAction` 与灰度统计显示 `waiting_user`。阶段历史按稳定 Scope 身份归属，重排阶段不会复用其他 Scope 的结果。Policy 预览和设备页另外返回服务端计算的闭合 `taskAdmission` 原因，不把单纯 Scope 命中称为可执行。读取要求 PolicyRead 与全设备 OperationRead；这些是当前动态目标的统计，历史任务证据不被重算。真实设备身份、可信用户交互和软件执行适配由 #2564 消费本协议，平台 T3 由 #2480/#2481 验收。

## 通道接入策略

MDM 与 Agent 各自持有 DeviceId、注册世代、凭据、采集和策略。MDM 来源字段 `channel.agent.installation` 的 `absent` 才能触发安装；Agent 来源 `channel.mdm.enrollment` 的 `unenrolled` 才能触发标准入口。可以将这些字段用于动态 Group，再通过 Scope 分配策略。当前有效来源的最新完整观察是依据，没有 TTL 或最后连接时间门槛；未知、失败、第三方 MDM 和旧注册观察不会变成缺失。

`ensure_agent_installed` 沿用 Software Resource / Content → Agent 包发布 → Group / Scope → Policy → execution-service。Action 使用 `packages` 按平台和架构显式选择一个发布 releaseId；没有 latest、格式回退、自动升级或格式迁移。发布需要全设备 SoftwareDeploy 与 Enrollment 授权，执行和下载复核当前授权、发布状态及冻结摘要。普通软件没有 Agent 发布记录时不能获得引导权限。

```json
{
  "kind": "ensure_agent_installed",
  "packages": {
    "windows_x86_64": "11111111-1111-4111-8111-111111111111",
    "macos_aarch64": "22222222-2222-4222-8222-222222222222"
  },
  "schedule": {"trigger": {"kind": "registration"}, "misfire": {"kind": "coalesce_one"}, "notBefore": 1792195200, "until": 1792281600, "jitterSeconds": 0, "window": null},
  "runLifetimeSeconds": 1800
}
```

示例 releaseId 应替换为本租户实际发布结果，schedule 使用未来的实际窗口；完整 Policy 外壳、Group / Scope 和 CAS 发布步骤沿用本指南前文。Windows release 可以选择 MSI 或 MSIX：MSI 使用 ProductCode、DownloadInstall 与原生状态；MSIX 使用单个签名应用包的 HostedInstall、PFN 和设备 provisioning，禁止 bundle、外部依赖、用户安装及未签名包。PKG 使用 InstallEnterpriseApplication。EXE 可公开下载和独立安装，不能用于 MDM 首装。

旧 `agent_installation` 配置已删除且拒绝解析。下载 origin 直接来自 `agent_pki.endpoint.origin`，包身份来自发布记录；不同架构无需共用安装身份。MDM→Agent 需要配置专用 `agent_pki.bootstrap` 与 `agent_bootstrap` PKI provider，详见[Agent 集成](agent-integration.md)。缺少引导 PKI 时不能发布此安装策略。

安装投递和引导证书投递是同一冻结安装授权下的独立操作。检测覆盖发布目录中的历史身份，包括已撤回包；任一格式存在或状态未明时不会启动第二个安装器。重叠策略共享排他与去重，不同 release 选择明确冲突。Scope 退出阻止尚未投递的新安装；已投递操作只在原期限、原策略版本、当前权限和来源世代仍有效时继续。Scope 退出不卸载 Agent。

Apple 新注册 profile 在启用该能力时申请已安装应用查询与企业应用安装 AccessRights；既有 profile 不会因服务器配置更新获得权限，需通过正常注册流程更新。采集要求 macOS 12+ 的明确 IsAppleSilicon 结果；Windows 只对明确的 64 位架构证据选择包。固定内容下载只暴露批准的包，不承载秘密，并复用单段 Range/ETag 和撤销检查。应分别读取操作中的原生 delivery、installation、独立 agentRegistration 与 capabilities；Acknowledged 不能证明安装完成。macOS 的 InstalledApplicationList 只证明同 bundle/version 的应用存在，不能核实签名 Team ID 或 PKG receipt，因此采集、策略诊断及原生 installation 均保持 unknown，不判 already_satisfied，也不据此重装。独立 Agent 注册及能力仍单独显示；配置中的 receipt/team 是批准产物的身份约束，不是设备侧签名证明。

`action:{kind:"request_mdm_enrollment",organization:"本租户 UUID",runLifetimeSeconds}` 使用部署 `enrollment_entries:{windows:"https://发现服务域名",macos:"https://注册页面"}`，需要全设备 Enrollment 权限和 Agent 的 `mdm.enrollment.v1` 能力。任务有签名 Offer/Start permit，Windows 打开标准注册 UI，macOS 打开 HTTPS 注册页面，保留系统、账户和用户确认。`enrollment_result` 的 `opened`、`user_required`、`third_party_conflict`、`unsupported`、`failed`、`unknown` 分开保存；取消使用独立的 `{kind:"cancelled"}` 事件。opened 不证明 MDM 已注册。自动触发在同一 Agent 注册下去重；未知执行阻止重试，管理员显式 rerun 仍受当前权限、观察、期限和取消约束。

两种动作分别配置与启停。服务端通过冻结授权、任务和真实协议事实保存可信关联，保留独立 Device / Registration，不按序列号合并。生产 Agent、安装包及真实 OS 验收由后续客户端任务消费本契约。

内容仓必须显式选择 `content.storage.kind=volume|s3`。服务端卷目录须存在、可写且为绝对路径；多实例共享同一目录。S3 配置参考 [S3 内容配置](../../fixtures/mdm-content-s3.example.json)，要求 HTTPS、启用版本控制的 bucket，以及指定 namespace 下对象读写和确切版本删除权限。实际对象前缀包含租户 UUID；下载始终经产品授权入口，不向客户端暴露 S3 凭据或地址。外部第三方下载 URL 不属于软件上传入口。

任意 PATCH 大小和字节偏移继续有效。普通内容按 128 MiB 完整块和一个尾快照保存，完成后冻结清单，不进行整包复制或 multipart 合成。请求体完整结束、对象校验和 PostgreSQL 提交后才确认偏移。原生配置与诊断的逻辑摘要保持明文身份，但所有持久对象都为受保护密文。只有 ZIP/MSIX 校验使用有额度限制的临时 seek 文件；普通下载按逻辑 Range 读取清单。

## 自助任务与调用参数

互注册默认不主动开启：管理员分别配置并启用 `ensure_agent_installed` 和 `request_mdm_enrollment` 策略。设备未注册只是状态，不产生授权。设置页主动申请 MDM 注册还要求对应策略发布 selfService；仅开放人工发起时将 schedule.trigger 设为 manual。自动与自助入口共用同一任务队列，未决或 Unknown 不创建第二个注册任务；停用策略不自动注销已经建立的通道身份。注册入口 outcome 为 opened 只代表已打开系统流程，最终注册由原生认证事实确认。


`Policy.definition.selfService` 用于脚本、AvailableInstall 软件和 `request_mdm_enrollment`。`access` 必须显式填写：`device` 允许有效设备 Scope 内的当前注册调用；`authenticated_user` 要求本租户有效企业会话；`users` 要求非空、有界、无重复的 selectors 至少匹配一个当前可信用户、IdP 组、部门（exact/subtree）或静态用户组。用户组与设备 Scope 分别判断，不建立 userScope。未发布草稿可显式填写 `access:null`；发布时不允许 null，省略字段不再接受。

管理员继续使用既有 Policy/Resource/Software 管理权限；普通员工无需 ScriptExecute 或 SoftwareDeploy。系统服务的执行权限不由员工管理员身份决定。Resource 的 System/LoggedInUser 保持原意；后者必须绑定确切 SID/UID、OS 登录世代和该会话的 helper，缺失或换人时阻止新 Start。

自助描述位于 selfService.presentation，AI 开关仍由 selfService.allowAi 持有。首次省略 allowAi/riskLevel 归一化为 true/2，编辑省略保留原值。脚本 riskLevel 仅允许 1、2；软件 riskLevel 只接受 2（省略时归一化为 2），AI 安装必须确认。关闭 allowAi 或撤回 published 只阻止自助调用，普通自动 Policy 独立判断。

Resource.Script 持有参数 schema，Policy 使用 Fixed/Input 选择来源。调用必须提交全部且仅提交 Input 键，不能覆盖 Fixed；后端合并后完整校验并冻结到 Run。存在 Input 时 trigger 必须为 manual。参数来源或固定值变化产生执行版本；访问和描述变化只推进配置 revision。软件和 MDM 注册调用 parameters 必须为空。

以下入口位于 `/api/v1/agent/runtime`，始终使用 Agent 系统服务的设备凭据。用户访问模式还使用 `X-RSS-User-Session`；设备模式不需要企业登录。无效或重复用户会话头不会降级为设备访问。系统服务根据真实 IPC 入口设置 source，模型参数不得控制 source，也不得接触设备私钥或企业凭据。confirmed 绑定当前 requestId、Policy revision/version 和确切输入，客户端边界由 #2677 实施。

- `GET /self-service?source=human|ai&after=<policyId>` 返回当前可调用的有界目录。每项含 Policy 坐标、自助描述及 tagged script/software/enrollment 接口。目录复用 Scope、注册世代、平台、能力、资源批准、频率、窗口、容量及 pending/Unknown 判断；未知事实不授予执行。
- `POST /self-service/invocations` 针对当前设备接受 operationId、Policy 坐标、source、confirmed、parameters，返回 202 的 requestId/runId。精确重试返回原 Run；变化正文返回冲突。AvailableInstall 在显式请求前不创建 Run/Offer，不能自行 Start；安装按确切资源版本、检测意图及稳定 Device/SID/UID 效果目标在用户和 Policy 之间排除重复，Unknown 不允许盲重试。
- `GET /self-service/invocations/{requestId}` 返回本主体、注册及世代对应的执行状态。原始脚本结果另外要求 InventoryRead，敏感采集还要求 InventorySensitiveRead；缺少读取权限时 result 为 null，状态仍可读。软件只返回闭合检测 outcome，原生证据与诊断继续由管理接口持有。

状态查询核对当前读者、当前注册与 Policy 访问资格及设备 Scope，不要求原企业会话或 OS/helper 仍可执行；这不签发新的执行许可。

Run 保存服务端选择的访问依据，用户模式只保存 Identity 签发的非凭据 SessionReference。领取及 Start 服务端复核原会话、账户和成员有效性、可信来源与快照期限、静态用户组、Policy revision/version、自助配置、有效设备 Scope 和确切 OS/helper。企业身份与 OS 账号分别绑定。签名覆盖通用 TaskAuthorization、精确输入和执行目标；客户端不能伪装成自动 Policy。

访问撤回阻止未启动任务。已启动执行按原 attempt 和不可变材料记录完成证据，企业退出登录不产生新的执行许可。执行状态与可信 Inventory 投影分别判断。安装使用当前初始化 schema；当前版本内的任务恢复消费原 attempt 与不可变材料。

契约由源码 owner 生成：管理 schema 见 `crates/management-http/schema/{PolicyWrite,Policy}.json`；调用 DTO 见 `crates/agent-wire/schema/runtime/self-service-*.json`；通用授权、资源坐标与签名任务以 task schema 为准。`agent-wire/examples/protocol_schema.rs` 从当前 Rust DTO 生成两族完整协议 schema；`hack/agent_wire_artifact.py --write` 物化 schema 并计算 fingerprint。协议包只提供规范签名字节；签名校验与本机执行条件由独立 Agent 持有，服务端执行资格和软件结果判定由产品 owner 持有。#2677/#2678 固定最终提交与契约指纹完成实际 Agent/员工 UI 集成；本 PR 的后端接缝结果不替代真机或浏览器闭环。软件本地检测及三 provider 产品验证继续归 #2657。

长上传在最终内容核验后复核原浏览器会话与当前权限，保持租户、实例、用户和 session 不变；复核不续会话 idle、不轮换凭据。传输期间会话撤销或权限失效时不创建内容绑定。镜像响应头等待、传输及绑定同样使用内容操作预算。

## 软件 Policy 的显式投递通道

软件 `action.channel` 只接受 `agent`、`mdm`；省略时输入边界保存为 `agent`。主机 `software_distribution.mdm_enabled` 默认 false，修改配置后重启生效；`GET /api/v1/policies/capabilities` 在 PolicyRead 授权下返回默认通道和开关。开关不改写策略。关闭时启用 MDM 软件返回 `mdm_software_disabled`，已排队但未开始原生执行的任务停止投递；已发出的副作用继续按原任务回收，不声称已撤销安装。

MDM v1 仅支持系统 MSI、签名单包 MSIX 的 device provisioning、签名 PKG。每个安装包的 `signatures[].evidence` 指向不可变报告 artifact；报告 JSON 持有 `sha256`、`mechanism`、`publisher`、`verified:true`，由平台打包/验证流程产生，经现有 Catalog 启用审批校验和固定。服务端验证报告与材料匹配，不执行平台签名工具。自定义环境/参数、依赖包、EXE、DMG、Bundle、用户安装、MDM 自助和卸载均不准入。MDM 仅接受 `reboot:report`、`downgrade:deny` 和标准退出码（success 为 `[0]`、reboot 为空）；MSI timeout 必须为整分钟且不超过 255 分钟。Agent 原有能力独立保留。

安装命令和下载都绑定原 action run、Policy/Resource 版本、注册世代及当前权限。切换通道产生新执行版本；未解决的安装效果按关联设备及所有包身份阻止重复写入，失败或离线不回退到另一通道。Windows MSI 通过原生 Status/Version，MSIX 通过精确 PackageFullName 的 IsProvisioned/Version 证明效果；缺失状态节点不算成功。PKG ACK 只证明协议受理，保持 Unknown，不推动成功率门禁。普通 PKG manifest 的 receipt 标识不被当作 InstalledApplicationList 的应用 bundle 标识。

当前 schema 与冻结输入不读取旧通道格式。已有数据库只使用与其安装清单匹配的原 artifact 恢复；部署新版本使用当前安装流程，不重写历史 ledger 或删除 Unknown 运行。设备上的安装真实性由独立产品 T3 验收提供。
