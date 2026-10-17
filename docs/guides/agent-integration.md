# Agent 注册与报告

服务端接入使用 [agent-wire](../../crates/agent-wire/README.md) 的闭合协议，版本、schema 和能力形态由协议包唯一持有。Agent 实现位于独立仓库；本指南不证明终端采集或执行已验收。

协议 crate 按私有 Git 的完整 rev 独立消费，最低 Rust 为 `1.96.0`，生产依赖闭包仅包含公共基础库。包含 PKI 制品的最终 rev 和三族 schema 指纹见 #2688 合入后的交付记录；独立 Agent #2685 在固定候选可实际获取后消费该版本，实现自己的密钥、可信时钟、签名校验和 OS 执行边界。协议包提供 `TaskPayload::signing_bytes` 与 `Trust::installation_digest`，不提供客户端验证器、执行决策或服务端业务模型。采集 DTO 在服务端 ingress 显式转成 Inventory 值；执行条件及软件证据判定仍由产品 owner 持有。

## API 版本与注册授权

注册生命周期为 `/api/v1/agent/enroll`，运行请求为 `/api/v1/agent/runtime`，二者独立演进。本次运行 JSON 的 `wireVersion: 1`、capability `*.v1` 和各任务签名域共同重建为新 V1。新 V1 继承当前 V6 的业务和安全语义，拒绝历史 V1 shape、V2–V6、旧 capability 与签名；未来由各族 owner 明确演进。[agent-wire](../../crates/agent-wire/README.md) 分别发布 `enroll`、`runtime`、`pki` schema 清单与指纹。PKI 保持独立的 `version: 1`；共享 Purpose 支持原生通道，Agent 必须显式拒绝非 Agent purpose，并继续核对 origin、租户、设备、注册、证书/CRL、时钟与防回滚。仅通过静态解码不授予安装或执行权限。

所有已认证租户用户可注册自己的设备，Agent 默认每用户 20 台，Windows 与 macOS 共用 Agent 额度；有效授权预留也计入占用。租户默认值与可空的个人覆盖见 [自助注册与个人额度](device-enrollment.md#自助注册与个人额度)，0 禁止新增并保留既有注册。授权默认 24 小时，最多 7 天；数据库只保存租户隔离的秘密摘要。

三种来源统一进入独立 Agent 证书链路：

1. 普通用户在 Agent 内登录企业会话。Agent 先通过 `POST /api/v1/agent/enroll/requests` 提交稳定 operationId、独立随机 secret、platform 与本机私钥签名的 base64 DER CSR；桌面会话调用 `POST /api/v1/agent-requests/{id}/authorize` 授权这一个请求。Agent 和网页消费由各自仓库交付；服务端不提供网页注册、确认页或深链接。所有新请求都必须绑定 CSR，客户端不能选择期限、数量或不限量。
2. 管理员调用 `POST /api/v1/agent-configurations` 创建一个完整签名 JSON 文件，必须明确 `quantity:{"kind":"finite","count":N}`（N > 0）或 `quantity:{"kind":"unlimited"}`，指定 targets 与 channels；可选 lifetimeSeconds 最多 365 天，默认后台 24 小时。管理客户端生成并保留 32 字节随机 secret；响应文件包含 configuration 元数据、secret 与 signature。相同创建 operation 和完整输入可重新取得原文件，数据库与审计不保存 secret。网页在请求提交后清除本地 secret；响应丢失时用原 operationId 调用 `GET /api/v1/agent-configuration-operations/{operationId}`，仅原创建主体和实例可读到无秘密元数据。返回 null 表示仍未知（原创建可能迟到提交），不得自动重新创建或恢复 secret；找到旧配置后先确认撤销成功，再创建新配置。`GET /api/v1/agent-configurations/{id}` 只返回元数据、状态、reserved、consumed 和 remaining；有限数量的 remaining 为 count−reserved−consumed，无限数量为 null，期限和撤销状态仍独立生效；`POST .../{id}/revoke` 禁止新交换。独立权限为 `agent_enrollment_read` / `agent_enrollment_write`。
3. 原生 MDM 安装使用专用短期引导证书，在 Agent TLS 监听器调用 `POST /api/v1/agent/enroll/native-grants`。提交 installationOperation、operationId、secret、独立日常密钥的 CSR 和 runtime；服务端从引导证书记录恢复来源注册、安装和 release，复查当前授权后返回 grant。原生 Windows / Apple 监听器不再挂载此入口，MDM 日常证书不能交换授权。

管理员配置使用配置自身的租户额度，默认责任人为 null；创建者仅作为审计身份，不占用其普通用户 20 台额度，也不构成终端 ownership。每台设备独立生成私钥、CSR、operation 和 grant secret，调用 `POST /api/v1/agent/enroll/configurations/exchange`，提交完整 file、runtime 和 installation（releaseId、candidateSha256）。同一 operation 的精确重试只返回原授权；同一配置下换 operation 重用 CSR 公钥被拒绝。`POST .../configurations/status` 使用原 configurationId、operationId 和独立设备 secret 查回授权，不重新分配。

有效、未签发 grant 预留配置名额；`POST /api/v1/agent/enroll/reservations/cancel` 以 grantId、原 creationOperationId、独立 secret 和稳定取消 operation 释放未消费名额。未签发授权到期也释放。第一次持久签发意图即永久计入 consumed，包含 Unknown，后续重装、撤销注册、重试或授权到期均不重置。配置到期或撤销只禁止新分配，已分配授权仍按冻结的短期 TTL 完成；已激活设备继续在线。

后台 `GET /api/v1/agent-enrollment-settings` 与 CAS `PUT` 统一持有 grantSeconds（默认 86400，上限 604800）、configurationDefaultSeconds（默认 86400，上限 31536000）和启用 platforms；PUT 使用 operationId、expectedRevision、values。GET／PUT 响应另提供 configurationFilename=`rss-agent-enrollment.json`，创建响应使用相同 Content-Disposition 文件名；将此 UTF-8 JSON 放在 EXE／PKG 同一目录供独立 Agent #2634 读取，不改签名文件或 Agent V1 schema。设置随数据库安装持久化，不从 `agent_pki.policy` 或客户端参数读取。新普通请求、配置交换、续期、恢复及原生 grant 都读取此设置；已有授权不延长、不因平台关闭而改写冻结期限。

持有 grant 的客户端调用 `POST /api/v1/agent/enroll/certificates`，提交 `wireVersion:1`、operationId、grantId、secret、CSR 和 runtime profile。服务端先持久化唯一签发意图，绑定 operation/CSR/SPKI，再请求 CA，并持久化已验证的候选证书链。精确重试返回相同候选；不同 operation、CSR 或 profile 拒绝。签发结果未知时保持同一个 issuanceId，不自动二次签发。

候选还不是活跃设备身份。客户端持本机私钥，在真实 mTLS 下调用 `/api/v1/agent/enroll/activate`，提交 issuanceId 与稳定 operationId。服务端在一个审计事务内复查原授权、期限、来源与证书，并创建独立 DeviceId、Registration、一个活跃凭据及冻结采集定义。CA 信任、原生证书、DeviceId、主机名、HTTP 转发头都不能单独建立 Agent 身份。

`POST /api/v1/agent/enroll/status` 用原 grantId/operationId/secret 查询持久进度。成功激活回执固定，ACK 丢失后重试原 operation；不能通过换 operation 绕开未知结果。普通用户取消未完成授权使用 `/api/v1/agent-requests/{id}/cancel`。注册后的撤销仍使用 `/api/v1/devices/{device}/registrations/{registration}/revoke`，要求资源级 credentials 权限。

## 同身份换证与未知签发恢复

当前有效 mTLS 设备手动调用 `/api/v1/agent/enroll/renewal-grants`；证书已过期或私钥丢失时，管理员通过 `/api/v1/agent-registrations/{id}/recovery` 创建短期恢复授权。两者复用同一候选签发和持有者激活路径，激活以原凭据为 CAS 前驱，仅替换凭据，保留 DeviceId、registration、generation、epoch、能力、采集定义和执行日志。旧凭据立即成为 retired，不能继续运行或续期。

续期授权已提交但响应丢失时，客户端以原 `wireVersion:1`、`operationId` 和 `secret` 调用 `POST /api/v1/agent/enroll/renewal-grants/status`，无需旧客户端证书即可取回原授权回执，再沿原 `/status`、签发与激活操作继续。该入口仅查询当前租户已有的续期授权，不创建授权、不延长期限、不重新签发；未知 operation 与错误 secret 均返回 `invalid_identity`。过期与撤销状态仍保留，不能据查询回执恢复在线业务权限。所有请求使用固定 HTTPS origin，不发送 Bearer。

未知签发由管理员找回 CA 中原始证书链，并通过 `/api/v1/agent-issuances/{id}/recover` 提交。服务端验证原 CSR、公钥、SAN 身份、签发窗口、直接签发者和 provisioner；禁止用重新签发的不同结果替代已保存候选。无法找回结果时不猜测成功，也不自动重签。

## 报告与状态

报告请求使用真实 mTLS；每次请求及业务事务都复查证书有效期与当前凭据状态。注册回执的 `collections` 返回服务端选择的冻结采集定义；报告必须携带对应完整 `collection` 对象，以及 wireVersion、reportId、sequence、observedAt、body。Agent 按 dataset 选择回执中的定义，不能自行增加字段或来源。普通字段值示例：

```json
{"field":"device.model","value":{"kind":"value","value":{"kind":"string","value":"Model A"}}}
```

snapshot、partial、failed 分别表达完整快照、部分结果和失败。空的成功快照与未执行、失败不同。通道状态也使用目录中声明的普通字段；不存在 `mdmEnrollment` 报告特例。字段身份、类型、来源和预算由冻结的定义决定，重复字段、定义外字段和未知 JSON 成员被拒绝。`POST /api/v1/agent/runtime/reports` 在不可变报告、摘要和成功审计提交后返回 202/durable；相同 reportId 与相同语义返回原 receivedAt，不同语义返回 409。

待投递报告达到有界容量时返回 service_unavailable，优先恢复既有 reportId。历史裁剪不得删除 pending 报告。Agent 与 Windows MDM 均由 `collection_runs` 持有不可变报告和最小交付进度，不存在第二套报告队列或 owner 分支。

恢复及 Agent 状态读取共同核对持久报告的 tenant、registration、source、epoch、dataset、reportId、sequence、coverage、规范字节和摘要，并要求报告已封存；数据库关系列与冻结报告内容不一致时拒绝恢复。

后台沿用唯一的 Inventory 运行时：保存不可变完整 CollectionRun 结果，通过有界摘要引用提交 Observation。产品投影验证引用和来源后应用成功字段；部分结果与失败不能清空旧事实，只有完整快照或显式 tombstone 能删除对应来源旧项。`GET /api/v1/agent/runtime/reports/{reportId}` 只允许当前有效 credential 读取当前注册/epoch 内的报告，返回 durable ack、Observation 状态与 Projection 状态。credential 被替换或撤销后，新报告和状态读取立即返回 401；替换前已提交的不可变报告仍可由后台恢复投递。

协议拒绝保留独立错误类别，不返回内部诊断或秘密。当前无已部署旧 Agent 的升级承诺；新注册须使用 V1，见 [运维](../deployment/operations.md)。企业任务签名、领取与启动许可见 [企业任务](enterprise-tasks.md)。

## Agent 上报本机 MDM 状态

具有 `mdm.enrollment.v1` 的 Agent 用 `/reports` 提交注册回执中对应的冻结 `collection`，并以 `body:{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":"unenrolled"}}}]}` 上报普通字段；其它闭合状态为 `this_organization`、`other_organization`、`unknown`。部分采集使用 `partial`，sequence 按该冻结采集定义的来源与 dataset 单调递增。该事实进入现有 CollectionRun、Observation、Inventory，字段为 `channel.mdm.enrollment`。标准入口任务的结果只说明入口是否打开，完成注册须由后续本机观察证明。

## 无兼容退出

旧 `/api/agent/v1`–`/api/agent/v6`、`/api/agent/enroll/v1` 和 `/api/agent/runtime/v1` 路由、Agent Bearer 凭据、Agent Enrollment 口令及原生直接注册入口全部退出，不提供别名或认证降级。数据库使用当前完整 schema 的全新安装和重放，已登记租户通过明确绑定宿主消费。原生 Windows/Apple 的五分钟 Enrollment 口令及 credential_ref 保留。真实 Agent、安装器、网页消费与真机验收在各自后续任务完成，受控服务端测试不代替这些证据。

## 当前 V1 软件执行上下文与结果

全部 Agent 注册（包括仅库存注册、托管安装注册）以及软件任务请求都必须包含完整 executionContext：递增 revision、OS 数字版本、systemBroker、绑定当前交互会话的 userHelper、明确 interactiveUser（没有会话时为 null）、来源范围只读凭据引用，以及 MSIX sideload/unsigned 能力。用户绑定包括精确 SID/UID 与 sessionId；上下文变化须使用更高 revision，旧 Offer 不能启动。每个依赖步骤分别检查 profile、执行上下文和材料；没有通用软件能力兜底。userHelper=false 阻止新的用户 Start，但不因该能力缺失而取消已启动任务的原 attempt 收尾。

软件结果是绑定 definitionDigest 的逐步骤证据：index/stepDigest、target、package、native identity、独立 before/after 检测、process、重启及诊断。MSIX 注册与 provisioning 使用不同 identity 变体，错误步骤、用户会话、包身份或作用域拒绝投影。退出码不能代替独立检测；Unknown 保留原任务恢复身份。当前 wire 为新 V1，只维护当前软件 shape 与指纹，消费方须更新精确依赖。

新 V1 继续拒绝软件 ownership 和 AppCopy 的 materialSha256，旧字段即使为 null 也拒绝；AppCopy 仍绑定完整 DMG 摘要、明确的包路径和目标名、bundle ID、版本、执行身份与独立前后检测。软件 Resource 继续沿用既有 V4 摘要域和持久化标记，其它 Resource 格式不变。独立 Agent #2663 须更新到本项交付的完整 Git rev 和两个 V1 指纹，当前服务端测试不代表 Agent 或真机已完成。

原生安装命令生成的固定包 URL 为 `/api/v1/agent/enroll/installations/{operation}/package`，origin 从现有 `agent_pki.endpoint.origin` 派生。引导下载每次验证固定安装 operation、有效期、原生注册、投递记录和业务授权。所有 runtime 入口要求 Agent mTLS。

## 固定安装包发布与匿名下载

服务器消费外部构建、签名和 notarization 完成的 Windows NSIS EXE、MSI、MSIX / macOS PKG，不在 Linux 构建或签名。固定包及候选 manifest 通过现有 Software Resource 和 Content 上传，来源注册即启用，版本由启用或安装包发布完成技术校验；候选 manifest 是独立、摘要校验的 Resource artifact。它冻结 wireVersion、tenantId、原生 target、version、HTTPS origin、signingKeys，以及 `packaging` 的 nsis_exe（publisher、signature_evidence）、windows_msi / windows_msix（publisher、signature_evidence）或 macos_pkg（bundle、team、notarization_evidence）外部证据。Windows EXE 的 Resource layout 仅声明固定 EXE 与该 manifest；PKG 同样拥有两份材料。公开下载返回被准入格式的固定包；响应的 format 与文件后缀必须一致。

`POST /api/v1/agent-packages` 要求 release_publish；草稿自动启用还要求 software_write，输入 operationId、resource、version、variant、target、channel、manifestArtifact。服务端验证两份材料的长度和摘要、完整当前软件生命周期与依赖闭包及系统安装范围，冻结 installerSha256 与独立 candidateSha256；服务器按 target 生成固定文件名，不接收包含秘密的名称或安装 argv。`POST /api/v1/agent-packages/{id}/withdraw` 要求 software_withdraw，阻止该候选的新交换和下载。外部打包及真实签名、notarization、导入、服务安装效果由产品 T3 验收；这些声明和受控服务端测试不代替平台证据。

Agent HTTPS 监听器公开 `GET /api/v1/agent/enroll/packages`、`GET .../packages/{id}` 与 `GET .../packages/{id}/content`，复用内容校验和 Range / ETag 下载。路径仅含公开 releaseId。配置不绑定一个固定软件版本；每次新交换检查当前发布、原生 target、允许 channel、可信 origin / key 和精确候选摘要。文件自身不能添加新的信任根。配置文件、共享 secret、设备 secret 和 CSR 不进入 URL、文件名或命令行。

本次移除旧 agent-grants 创建、管理状态、preview / approve 路由和普通请求 lifetimeSeconds / 可选 CSR，不提供别名或兼容解码；保留的是既有设备身份、不可变回执和 Unknown 恢复事实。

原生声明式采集使用 `agent_collection` 资源及 Collection 任务，协议形态、引擎要求和固定签名向量见 [wire 契约](../../crates/agent-wire/README.md#原生采集契约2739)，配置及质量语义见[资产指南](assets.md#windows-agent-声明式采集)。当前 task payload 显式携带 kind/task，claim environment 必须包含 nativeEngines；不兼容旧包络，不使用脚本兜底。

安全、账户、证书和更新由同一原生 Collection V3 契约承载，见 [wire 契约](../../crates/agent-wire/README.md#安全账户证书与更新)
和 [标准包操作](assets.md#agent-安全账户证书与更新标准包)。Agent 必须固定交付的完整 revision，
更新当前用户 GeneratedUID、精确引擎声明及 scan 证据；不沿用旧 Collection V2 或省略新增必填成员。
本候选只接纳匹配的精确安装 manifest，不承诺旧数据库原地升级。旧实例按原版本结算任务并保留注册、journal、审计和历史资产，不清库或重新注册绕过安装拒绝；任务排空不等于持久格式迁移完成。

## 原生互注册的前置条件与流程

MDM→Agent 的前置条件是有效的原生注册、当前设备管理权限、已启用且经 Agent 发布准入的固定包、当前 Group / Scope / Policy 授权，以及产品 PKI 的专用 `agent_bootstrap` 信任与 SCEP provisioner。Windows 需要设备级 SCEP CSP 和相应应用部署 CSP；macOS 需要 Profile/SCEP、企业应用安装和应用查询权限。设备应已信任 SCEP CA 与 Agent HTTPS 服务端证书，能访问相应 HTTPS origin。安装包签名信任、私钥 ACL、Agent 服务读取系统证书及无人登录运行由平台交付验证。

在既有 `agent_pki` 的 `step_ca` 配置内增加以下块；文件使用部署秘密权限，密钥内容是 step-ca 返回的 base64 HMAC key。`device_pki` 中另配置 purpose=`agent_bootstrap` 的现有 provider，绑定信任中相同 issuer 及其 `scep_url`。独立信任文件的 purpose 必须是 `agent_bootstrap`，origin 必须等于 Agent HTTPS origin。

```json
{
  "bootstrap": {
    "trust_file": "/etc/rss-mdm/agent-bootstrap-trust.json",
    "challenge_id": "bootstrap-challenge",
    "challenge_key_file": "/run/secrets/bootstrap-challenge.key",
    "notify_id": "bootstrap-notify",
    "notify_key_file": "/run/secrets/bootstrap-notify.key"
  }
}
```

SCEP provisioner 的挑战和签发通知 webhook 分别指向 Agent origin 的 `/api/v1/agent/enroll/bootstrap/scep/challenge` 与 `/notify`，启用签名原始请求和时间戳校验。挑战 webhook 名称设为 `rss`，证书模板仅消费服务端批准的字段：

```json
{
  "subject": {{ toJson .Webhooks.rss.subject }},
  "notAfter": {{ toJson .Webhooks.rss.notAfter }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "basicConstraints": {"isCA": false}
}
```

模板不继承 CSR 中的 SAN 或任意扩展，CA 的有效期约束应允许服务端给出的短期限。参考 [step-ca 模板](https://smallstep.com/docs/step-ca/templates/) 和 [Windows SCEP CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/clientcertificateinstall-csp)。

1. 策略冻结 release、来源世代及安装授权；服务端创建独立引导投递，期限不超过安装期限和 30 分钟。
2. Windows 由设备级 SCEP CSP、macOS 由 Profile/SCEP 产生引导私钥。安装包单独投递；包、下载 URL 和安装参数均不携带引导秘密。
3. 未签发的引导投递沿用原安装总期限，短期证书期限从实际 SCEP challenge 起算，最长 30 分钟且不超过原总期限。挑战校验安装、来源、投递、发布和权限，冻结 CSR/SPKI/事务；同请求响应丢失可精确重试，不同请求拒绝。签发通知验证真实证书并保存指纹。已知签发、过期且尚未交换 grant 的尝试可在原授权内更换引导尝试，保留旧记录且不重装；signing 结果未知不会自动重签。
4. Agent 用该证书完成专用 mTLS，另行产生日常密钥和 CSR。交换后的 grant 已绑定日常公钥，继续受自身及原安装期限、当前来源与权限限制，不因已消费引导证书自然到期而失效。服务端拒绝引导与日常密钥复用；现有 grant → certificates → activate 完成后保存可信关联，并通过原生通道清理引导配置。清理仅针对该操作的确切 SCEP/Profile 对象，独立于之后的策略启停或包撤回；确认原生命令成功后才结束，过期/拒绝保留原历史并重排清理。
5. 独立日常身份按已有续期与撤销路径存续；包已下载、安装 ACK、MSIX provisioning 均不能证明 Agent 已激活或服务在线。

Agent→MDM 复用 `request_mdm_enrollment` 的签名任务和 Start permit。只有已启动任务的当前 Agent 可以 `POST /api/v1/agent/runtime/tasks/{task}/enrollment`，提交稳定 operationId、attemptId 和客户端生成的 password；服务端仅存口令摘要。返回短期 enrollmentId、期限及平台入口，Windows 还提供用户名、macOS 提供 profileUrl。客户端保留用户系统确认；入口 opened 或客户端报告不建立原生注册事实，必须经 Windows 认证签入，或 Apple Authenticate、TokenUpdate 与当前准入。两端 Device/Registration 独立，仅按服务端请求关联。

诊断从既有 Policy assignment 与 operation API 读取：先核对 taskAdmission 的包选择和当前授权，再查看 agentInstallation 中的 delivery、installation、bootstrap（state / delivery / cleanup / deadline）和 agentRegistration。EXE 沿用 Software 定义的系统 Uninstall registry / DisplayVersion 检测信息，通过现有 Win32 清单遍历核对；文件检测或其它无法映射为可靠原生证据的发布保持 unknown。目录变化使旧缺失证据失效。未知安装或其它格式已存在时继续核实原状态，不换包重装。撤回发布会阻止新下载和交换。#2636 的服务端验证与交接不依赖实际 Agent 包制作、代码签名配置或真机验收；这些由后续任务承担。
