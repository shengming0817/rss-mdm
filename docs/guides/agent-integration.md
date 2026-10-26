# Agent 注册与报告

服务端接入使用 [agent-wire](../../crates/agent-wire/README.md) 的闭合协议，版本、schema 和能力形态由协议包唯一持有。Agent 实现位于独立仓库；本指南不证明终端采集或执行已验收。

协议 crate 按私有 Git 的完整 rev 独立消费，最低 Rust 为 `1.96.0`，生产依赖闭包仅包含公共基础库。最终完整 rev 和五族 schema 指纹以当前候选交付记录为准；独立 Agent 在固定候选可实际获取后消费该版本，实现自己的密钥、可信时钟、签名校验和 OS 执行边界。协议包提供 `TaskPayload::signing_bytes` 与 `Trust::installation_digest`，不提供客户端验证器、执行决策或服务端业务模型。采集 DTO 在服务端 ingress 显式转成 Inventory 值；执行条件及软件证据判定仍由产品 owner 持有。

## API 版本与注册授权

注册生命周期为 `/api/v1/agent/enroll`，运行请求为 `/api/v1/agent/runtime`，二者独立演进。本次运行 JSON 的 `wireVersion: 1`、capability `*.v1` 和各任务签名域共同重建为新 V1。仅维护当前 V1 结构及其业务、安全与恢复语义，不提供历史格式兼容。[agent-wire](../../crates/agent-wire/README.md) 分别发布 `enroll`、`runtime`、`task_trust`、`pki`、`connections` schema 清单与指纹。PKI 保持独立的 `version: 1`；共享 Purpose 支持原生通道，Agent 必须显式拒绝非 Agent purpose，并继续核对稳定 serviceId、租户、设备、注册、证书/CRL、时钟与防回滚。仅通过静态解码不授予安装或执行权限。

所有已认证租户用户可注册自己的设备，Agent 默认每用户 20 台，Windows 与 macOS 共用 Agent 额度；有效授权预留也计入占用。租户默认值与可空的个人覆盖见 [自助注册与个人额度](device-enrollment.md#自助注册与个人额度)，0 禁止新增并保留既有注册。授权默认 24 小时，最多 7 天；数据库只保存租户隔离的秘密摘要。

三种来源统一进入独立 Agent 证书链路：

1. 普通用户在 Agent 内登录企业会话。Agent 先通过 `POST /api/v1/agent/enroll/requests` 提交稳定 operationId、独立随机 secret、platform 与本机私钥签名的 base64 DER CSR；桌面会话调用 `POST /api/v1/agent-requests/{id}/authorize` 授权这一个请求。Agent 和网页消费由各自仓库交付；服务端不提供网页注册、确认页或深链接。所有新请求都必须绑定 CSR，客户端不能选择期限、数量或不限量。
2. 管理员调用 `POST /api/v1/agent-configurations` 创建一个完整签名 JSON 文件，必须明确 `quantity:{"kind":"finite","count":N}`（N > 0）或 `quantity:{"kind":"unlimited"}`，指定原生 targets；可选 lifetimeSeconds 最多 365 天，默认后台 24 小时。管理客户端生成并保留 32 字节随机 secret；响应文件包含 configuration 元数据、secret 与 signature。相同创建 operation 和完整输入可重新取得原文件，数据库与审计不保存 secret。网页在请求提交后清除本地 secret；响应丢失时用原 operationId 调用 `GET /api/v1/agent-configuration-operations/{operationId}`，仅原创建主体和实例可读到无秘密元数据。返回 null 表示仍未知（原创建可能迟到提交），不得自动重新创建或恢复 secret；找到旧配置后先确认撤销成功，再创建新配置。`GET /api/v1/agent-configurations/{id}` 只返回元数据、状态、reserved、consumed 和 remaining；有限数量的 remaining 为 count−reserved−consumed，无限数量为 null，期限和撤销状态仍独立生效；`POST .../{id}/revoke` 禁止新交换。独立权限为 `agent_enrollment_read` / `agent_enrollment_write`。
3. 原生 MDM 安装使用专用短期引导证书，经 Nginx Agent 公开入口调用 `POST /api/v1/agent/enroll/native-grants`。提交 installationOperation、operationId、secret、独立日常密钥的 CSR 和 runtime；服务端从引导证书记录恢复来源注册、安装和 release，复查当前授权后返回 grant。Windows / Apple 原生协议路由不挂载此入口，MDM 日常证书不能交换授权。

管理员配置使用配置自身的租户额度，默认责任人为 null；创建者仅作为审计身份，不占用其普通用户 20 台额度，也不构成终端 ownership。每台设备独立生成私钥、CSR、operation 和 grant secret，调用 `POST /api/v1/agent/enroll/configurations/exchange`，提交完整 file、runtime 和 installation（releaseId）。同一 operation 的精确重试只返回原授权；同一配置下换 operation 重用 CSR 公钥被拒绝。`POST .../configurations/status` 使用原 configurationId、operationId 和独立设备 secret 查回授权，不重新分配。

有效、未签发 grant 预留配置名额；`POST /api/v1/agent/enroll/reservations/cancel` 以 grantId、原 creationOperationId、独立 secret 和稳定取消 operation 释放未消费名额。未签发授权到期也释放。第一次持久签发意图即永久计入 consumed，包含 Unknown，后续重装、撤销注册、重试或授权到期均不重置。配置到期或撤销只禁止新分配，已分配授权仍按冻结的短期 TTL 完成；已激活设备继续在线。

后台 `GET /api/v1/agent-enrollment-settings` 与 CAS `PUT` 统一持有 grantSeconds（默认 86400，上限 604800）、configurationDefaultSeconds（默认 86400，上限 31536000）和启用 platforms；PUT 使用 operationId、expectedRevision、values。GET／PUT 响应另提供 configurationFilename=`rss-agent-enrollment.json`，创建响应使用相同 Content-Disposition 文件名；将此 UTF-8 JSON 放在 EXE／PKG 同一目录供独立 Agent #2634 读取，不改签名文件或 Agent V1 schema。设置随数据库安装持久化，不从 `agent_pki.policy` 或客户端参数读取。新普通请求、配置交换、续期、恢复及原生 grant 都读取此设置；已有授权不延长、不因平台关闭而改写冻结期限。

持有 grant 的客户端调用 `POST /api/v1/agent/enroll/certificates`，提交 `wireVersion:1`、operationId、grantId、secret、CSR 和 runtime profile。服务端先持久化唯一签发意图，绑定 operation/CSR/SPKI，再请求 CA，并持久化已验证的候选证书链。精确重试返回相同候选；不同 operation、CSR 或 profile 拒绝。签发结果未知时保持同一个 issuanceId，不自动二次签发。

候选还不是活跃设备身份。客户端持本机私钥，在真实 mTLS 下调用 `/api/v1/agent/enroll/activate`，提交 issuanceId 与稳定 operationId。服务端在一个审计事务内复查原授权、期限、来源与证书，并创建独立 DeviceId、Registration、一个活跃凭据及冻结采集定义。CA 信任、原生证书、DeviceId、主机名、HTTP 转发头都不能单独建立 Agent 身份。

`POST /api/v1/agent/enroll/status` 用原 grantId/operationId/secret 查询持久进度。成功激活回执固定，ACK 丢失后重试原 operation；不能通过换 operation 绕开未知结果。普通用户取消未完成授权使用 `/api/v1/agent-requests/{id}/cancel`。注册后的撤销仍使用 `/api/v1/devices/{device}/registrations/{registration}/revoke`，要求资源级 credentials 权限。

## 同身份换证与未知签发恢复

当前有效 mTLS 设备手动调用 `/api/v1/agent/enroll/renewal-grants`；证书已过期或私钥丢失时，管理员通过 `/api/v1/agent-registrations/{id}/recovery` 创建短期恢复授权。两者复用同一候选签发和持有者激活路径，激活以原凭据为 CAS 前驱，仅替换凭据，保留 DeviceId、registration、generation、epoch、能力、采集定义和执行日志。旧凭据立即成为 retired，不能继续运行或续期。

续期授权已提交但响应丢失时，客户端以原 `wireVersion:1`、`operationId` 和 `secret` 调用 `POST /api/v1/agent/enroll/renewal-grants/status`，无需旧客户端证书即可取回原授权回执，再沿原 `/status`、签发与激活操作继续。该入口仅查询当前租户已有的续期授权，不创建授权、不延长期限、不重新签发；未知 operation 与错误 secret 均返回 `invalid_identity`。过期与撤销状态仍保留，不能据查询回执恢复在线业务权限。请求只使用已安装签名连接配置中的 HTTPS origins，不发送 Bearer。

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

新 V1 继续拒绝软件 ownership 和 AppCopy 的 materialSha256，旧字段即使为 null 也拒绝；AppCopy 仍绑定完整 DMG 摘要、明确的包路径和目标名、bundle ID、版本、执行身份与独立前后检测。独立 Agent #2663 须更新到本项交付的完整 Git rev 和两个 V1 指纹，当前服务端测试不代表 Agent 或真机已完成。

原生安装命令生成的固定包 URL 为 `/api/v1/agent/enroll/installations/{operation}/package`，origin 在接受新任务时从当前已发布签名连接配置的 `preferredOrigin` 冻结；已有任务保留原地址，其未完成期间阻止该地址退役。引导下载每次验证固定安装 operation、有效期、原生注册、投递记录和业务授权。所有 runtime 入口要求 Agent mTLS。

## 固定安装包发布与匿名下载

服务器接收外部构建的 Windows EXE/MSI/MSIX 与 macOS PKG，不在 Linux 构建、签名或执行安装包。上传完成时验证原文件长度和摘要；默认只对不超过 1 GiB 的文件尝试辅助识别，较大文件跳过解析，不为解析复制临时文件。目录安全预算统一为 4096（含清单），超限仅停止解析。PKG 只读取 PackageInfo/Distribution，MSIX 只读取固定清单，MSI/EXE 只读取必要属性；不展开 Payload/CAB 或逐个验证业务载荷。

识别结果与原文件一起持久保存。查看、保存和发布复用既有结果，不重新读取或解析安装包；原文件下载仍校验本次读取的完整性。未解析、预算超限或解析失败的包可由管理员补填版本和目标后保存、发布；具有完整合法执行定义时可生成安装任务。辅助识别不构成软件可信、签名有效或可成功安装的证明，实际效果由终端/OS核实。未签名、ad-hoc 或未公证均不因该原因被拒绝。

管理客户端自动生成并保留稳定 operationId：

1. `POST /api/v1/agent-packages/uploads` 提交 filename、length、sha256，取得系统生成的 package/resource/upload 坐标和上传 href。摘要只保证文件完整性，不证明作者可信。
2. 沿现有 Content href 使用 GET 查询、PATCH `?offset=N` 续传和 POST `/complete` 完成；响应丢失先读取原上传状态，不换操作。`GET /api/v1/agent-packages/uploads/{packageId}` 读取持久解析状态和可选观察结果；GET 不触发解析。有效上传可显式 POST 同一路径请求解析（包括大文件），已存在结果直接复用。
3. `POST /api/v1/agent-packages/save` 提交 operationId、packageId、可选 version、target 与可选完整 behavior（既有 SoftwareBehavior 合同，主安装材料键固定为 package）。behavior 与材料一次保存为不可变版本，由 Resource 校验格式、目标、引用、参数和检测规则；省略或 null 表示没有执行定义。系统保存既有 Software Resource、私有来源和版本，返回可回读的软件 href；文件原名归 Resource 展示，文件事实与软件生命周期仍由原 owner 持有。未提供安装执行定义不阻塞保存或发布；实际生成安装任务时才要求完整执行定义，不能猜测 EXE 静默参数。
4. `POST /api/v1/agent-packages` 只提交 operationId、packageId，要求 release_publish；自动启用软件仍检查 software_write。发布绑定真实安装文件与当前软件生命周期，显式启用后的正常 ARM64 EXE 与 PKG 沿用同一链路；领域拒绝与权限拒绝分别返回闭合原因。首用采用 production。四个原生目标及同目标多个版本可共存，一个已发布包即可满足首用包条件。
5. `GET /api/v1/agent-packages/operations/{operationId}` 查询原保存、发布或撤回结果；null 表示仍未知，不证明未提交。`POST /api/v1/agent-packages/{releaseId}/withdraw` 要求 software_withdraw，禁止该 release 的新交换与下载。

Nginx Agent 路由公开 `GET /api/v1/agent/enroll/packages`、`GET .../packages/{id}` 与 `GET .../packages/{id}/content`，继续复用 Content 的长度、摘要、Range 和 ETag。包目录只描述已发布安装材料，不承载注册 origin、公钥或构建期候选声明。注册 installation 只引用不可变 releaseId；文件摘要由软件 owner 持有，不另交付候选 manifest。

注册配置仍由注册 owner 签名并验证稳定服务身份、签名连接配置、租户、目标、期限、secret、数量及 CSR；当前发布状态在同一租户事务中复查。任务签名与运行身份不因包未签名而改变。配置、共享 secret、设备 secret 和 CSR 不进入 URL、文件名或命令行。

本项直接替换当前自有 V1，不接受旧 manifestArtifact、candidateSha256、包内 origin/signingKeys 或旧 nsis_exe 发行合同。前端与独立 Agent 必须同步消费本次完整 revision；服务端通过不代表旧客户端已接入或真机通过。发布成功不表示目标操作系统一定允许安装，真实拒绝和执行结果由原通道如实返回，系统不关闭或绕过 OS 策略。

随附 Nginx 在同域或分离的公开 HTTPS origin 上代理注册、签发、激活与运行路径，统一进入隔离的内部 HTTP adapter。匿名安装包下载复用软件目录 owner，保留 Range / ETag。管理会话只发送到控制台同源管理 API；设备入口清除 Cookie，Agent 路由也清除 Authorization，证书身份由网关的真实 TLS 证明与后端领域核验共同确定。

本次移除旧 agent-grants 创建、管理状态、preview / approve 路由和普通请求 lifetimeSeconds / 可选 CSR，不提供别名或兼容解码；保留的是既有设备身份、不可变回执和 Unknown 恢复事实。

原生声明式采集使用 `agent_collection` 资源及 Collection 任务，协议形态、引擎要求和固定签名向量见 [wire 契约](../../crates/agent-wire/README.md#原生采集契约2739)，配置及质量语义见[资产指南](assets.md#windows-agent-声明式采集)。当前 task payload 显式携带 kind/task，claim environment 必须包含 nativeEngines；不兼容旧包络，不使用脚本兜底。

安全、账户、证书和更新由同一原生 Collection V1 契约承载，见 [wire 契约](../../crates/agent-wire/README.md#安全账户证书与更新)
和 [标准包操作](assets.md#agent-安全账户证书与更新标准包)。Agent 必须固定交付的完整 revision，
使用当前用户 GeneratedUID、精确引擎声明及 scan 证据。
本候选只接纳匹配的精确安装 manifest，不承诺旧数据库原地升级。旧实例按原版本结算任务并保留注册、journal、审计和历史资产，不清库或重新注册绕过安装拒绝；任务排空不等于持久格式迁移完成。

## 原生互注册的前置条件与流程

MDM→Agent 的前置条件是有效的原生注册、当前设备管理权限、已启用且经 Agent 发布准入的固定包、当前 Group / Scope / Policy 授权，以及产品 PKI 的专用 `agent_bootstrap` 信任与 SCEP provisioner。Windows 需要设备级 SCEP CSP 和相应应用部署 CSP；macOS 需要 Profile/SCEP、企业应用安装和应用查询权限。设备应已信任 SCEP CA 与 Agent HTTPS 服务端证书，能访问相应 HTTPS origin。安装包签名信任、私钥 ACL、Agent 服务读取系统证书及无人登录运行由平台交付验证。

在既有 `agent_pki` 的 `step_ca` 配置内增加以下块；文件使用部署秘密权限，密钥内容是 step-ca 返回的 base64 HMAC key。`device_pki` 中另配置 purpose=`agent_bootstrap` 的现有 provider，绑定信任中相同 issuer 及其 `scep_url`。独立信任文件的 purpose 必须是 `agent_bootstrap`，origin 必须等于 Agent HTTPS origin。

```json
{
  "bootstrap": {
    "trust_file": "/etc/rss-mdm/agent-bootstrap-trust.json",
    "webhooks": [{"issuer":"REPLACE-issuer-sha256",
      "challenge":{"id":"bootstrap-challenge","secret_file":"/run/secrets/bootstrap-challenge.key"},
      "notify":{"id":"bootstrap-notify","secret_file":"/run/secrets/bootstrap-notify.key"}}]
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
4. Agent 用该证书完成专用 mTLS，另行产生日常密钥和 CSR。交换后的 grant 已绑定日常公钥，继续受自身及原安装期限、当前来源与权限限制，不因已消费引导证书自然到期而失效。服务端拒绝引导与日常密钥复用；现有 grant → certificates → activate 完成后保存可信关联，并通过原生通道清理引导配置。每次尝试分别持有清理职责，当前身份清理完成不会撤销历史尝试的重试资格；命令授权绑定确切 bootstrap ID，并仅允许对应 SCEP/Profile 删除。清理仅针对该操作的确切 SCEP/Profile 对象，独立于之后的策略启停或包撤回；确认原生命令成功后才结束，过期/拒绝保留原历史并重排清理。
5. 独立日常身份按已有续期与撤销路径存续；包已下载、安装 ACK、MSIX provisioning 均不能证明 Agent 已激活或服务在线。

Agent→MDM 复用 `request_mdm_enrollment` 的签名任务和 Start permit。只有已启动任务的当前 Agent 可以 `POST /api/v1/agent/runtime/tasks/{task}/enrollment`，提交稳定 operationId、attemptId 和客户端生成的 password；服务端仅存口令摘要。返回短期 enrollmentId、期限及平台入口，Windows 还提供用户名、macOS 提供 profileUrl。客户端保留用户系统确认；入口 opened 或客户端报告不建立原生注册事实，必须经 Windows 认证签入，或 Apple Authenticate、TokenUpdate 与当前准入。两端 Device/Registration 独立，仅按服务端请求关联。

诊断从既有 Policy assignment 与 operation API 读取：先核对 taskAdmission 的包选择和当前授权，再查看 agentInstallation 中的 delivery、installation、bootstrap（state / delivery / cleanup / deadline）和 agentRegistration。EXE 沿用 Software 定义的系统 Uninstall registry / DisplayVersion 检测信息，通过现有 Win32 清单遍历核对；文件检测或其它无法映射为可靠原生证据的发布保持 unknown。目录变化使旧缺失证据失效。未知安装或其它格式已存在时继续核实原状态，不换包重装。撤回发布会阻止新下载和交换。#2636 的服务端验证与交接不依赖实际 Agent 包制作、代码签名配置或真机验收；这些由后续任务承担。


## 稳定身份与签名连接配置

服务身份固定为安装 `instance_id` 与 tenant，网络地址可变。注册文件包含当前 `connections::SignedConfiguration`；设备安装材料通过受保护的交付绑定该身份、配置验证公钥与 HTTPS CA。配置签名根归注册 owner 持有，复用原 Ed25519 与 Native 密文保护设施，独立于任务密钥轮换。

管理员通过同源 `GET/PUT /api/v1/agent-connections` 读取和保存 draft，通过 `POST /api/v1/agent-connections/publish` 发布指定 revision；保存不表示部署或生效。写入使用原 operationId、CAS revision 和近期会话，未知结果先查询 `GET /api/v1/agent-connection-operations/{id}`，null 只表示仍未知。`GET /api/v1/registration-channels` 展示实际配置的各公开入口。Nginx 部署与逐 origin 的 HTTPS 观察由原宿主维护流程持有，发布要求观察对应当前 draft revision 且在最近五分钟内，网页不执行部署操作。

设备通过已认证的 `GET /api/v1/agent/enroll/connections` 获取签名配置，使用已安装公钥验签，拒绝跨服务/租户、回滚、同 revision 异内容或非规范 origin，原子保存并读回后才使用。`POST .../connections/acknowledgements` 绑定 registration、generation、revision、摘要与真实网关 origin；`POST .../connections/failures` 只记录闭合失败原因，不改变已安装 revision 或授权。管理端通过设备 observation 和带 target revision 的 `/agent-connections/devices` 分页分别读取实际 ACK、失败与未确认设备。

发布采用 `A → A+B → B`，重叠阶段优先 B，设备经 B 确认后才允许移除 A。`connection_deployment_unobserved` 和 `connection_retirement_blocked` 为明确发布阻断。所有已知地址失联时，通过受保护的 `GET /api/v1/agent-connections/configuration` 下载和离线导入恢复。导入不能扩大 CA、凭据或业务权限；通信状态、密钥命名空间、执行 authority 与内容缓存都绑定稳定身份。正常入口和程序更新保留原注册、世代、执行日志及未决操作。Windows/Apple 原生 URL 由各自协议配置持有。

管理员签发恢复的未知响应先查询 `GET /api/v1/agent-issuances/{id}/recovery-operations/{operation}`。查询复核当前设备凭据权限及原主体/实例，找到原回执才显示成功；null 不证明回滚，只能由用户显式原样重试。浏览器不签名、不持有 CA 或配置私钥。

## 任务签名信任与安装确认

任务签名信任独立于设备 PKI 的证书信任版本，复用已认证 Agent mTLS 通道。`GET /api/v1/agent/runtime/task-trust` 返回稳定服务身份和租户绑定的完整 Ed25519 公钥集合；Agent 先验证版本单调性、既有 key ID 的公钥不变、唯一 active key，再持久保存并读回。只有完成这些步骤后，才向同一路径 POST 安装 ACK。ACK 固定原 operation、registration、generation、revision 和完整集合摘要；响应未知时重放同一 ACK，不能将收到响应正文等同于本地持久化成功。正式 DTO 与 schema 见 [任务信任](../../crates/agent-wire/src/task_trust.rs) 和 [manifest](../../crates/agent-wire/schema/task_trust/manifest.json)。

租户管理通过 `GET/POST /api/v1/task-signing/trust` 读取、准备或激活密钥，写入使用 `Idempotency-Key`、`expectedRevision` 和近期真实管理员会话。准备新密钥只发布 prepared 公钥；所有当前 Agent 注册世代确认包含该键的准备版本后才能激活。任务发放再次核对当前 active key 和目标设备 ACK，覆盖分发期间新注册的设备。原键转为 verify_only，保留历史验证材料。新激活键由受控重启消费，旧进程不能继续用已退出 active 状态的键签发任务。准备阶段仍有效的旧签名权威可以重启加载。

`GET /api/v1/task-signing/operations/{id}` 查询原管理操作，后续轮换不会改写其结果。该服务端合同不代表 Agent 已实现持久安装；Agent 消费实现与真实设备资格由对应后续任务验收。


设备分别向 `POST /api/v1/agent/runtime/task-trust/observations` 与
`POST /api/v1/agent/enroll/trust/observations` 上报任务信任、Agent PKI 的安装观察。
两者使用各自正式 DTO；保持原注册世代和单调观察序号，响应丢失重放原 operation 与正文。
目标获取失败可不填目标版本和摘要；无法读回时不声称已应用。失败原因仅使用闭合枚举，不发送证书、秘密或原始错误。

管理侧使用设备的 `InventoryRead` 权限查询
`GET /api/v1/task-signing/trust/devices/{device}/observation` 或
`GET /api/v1/pki/agent/trust/devices/{device}/observation`。
结果只代表当前注册世代最后序号的设备观察，另带服务端接收时间；无记录返回 null，表示未知。
迟到的旧报告不会覆盖新结果。同一操作或序号的异内容报告被拒绝。
失联时只能展示最后观察及时间，不能据此宣称当前在线或仍然已应用。
这些接口不创建成功 ACK，也不满足密钥激活门槛；PKI 安装摘要不包含 CRL 刷新内容，不能作为 CRL 新鲜度证明。
离线设备可让轮换继续待完成，但无需等待其 ACK 才能部署、启动或开通租户。

升级保留现有注册、设备证书、发布包与配置的原始历史记录。新下载的注册文件不含发布环；已用完或旧格式文件不转换、不重签，后续设备由管理员生成当前格式文件。Agent 的 trust Applied/ACK 表示其私有信任集合已持久应用并读回，不要求将设备 CA 安装为宿主的全局根信任。

## 周期遥测配置

遥测沿用 runtime family 和已认证 mTLS 通道，通过 `telemetry.collect.v1` 显式声明能力；不会退回普通报告或一次性任务。目录与接口见[资产指南](assets.md)。配置响应为 `SignedTelemetryConfiguration`，复用现有任务签名信任、active key 与当前注册代际的持久安装 ACK。协议包的 `TelemetryConfiguration::signing_bytes` 定义独立签名域；Agent 按既有任务信任验证签名，并核对本地 tenant/device/registration/generation/source epoch 与可信 UTC 时钟。

配置是最长五分钟的执行租约。到期后停止开始采集并重新获取配置，不能用旧签名、旧注册或 mTLS 本身代替新授权。提频有单独的固定 UTC 到期时间；在有效租约内到期时恢复正常周期。有效租约仍需执行外层运行时间、输出和上传预算，脚本参数只作为字面量传递。材料由精确配置的受保护内容入口读取并核对长度与 SHA-256；配置、采集输出或设备日志均不能自行授予来源权限。

采样 ID 在租户内固定原配置及内容，重组批次不重发同一事实；Counter 的标量区间起点属于每个字段读数，结构化 Counter 从已声明的元素路径读取各资源起点。上传未知时保留原 batch ID、采样 ID、绑定和内容，按原身份查询或重放。服务端签名与协议测试不代表 Agent 周期采样、离线缓存或真实设备 T3 已实现。

## 当前扩展对象与一次性字段切换

当前开发基线直接使用新结构，不保留旧 DTO、字段别名或历史格式读取。

| 消费位置 | 当前路径与约束 |
|---|---|
| SelfService 目录与管理定义 | 六类文案移到 `selfService.presentation`；授权、风险和版本仍在原核心结构。 |
| Resource/软件目录与 Blueprint | 对象展示与 blueprint category 位于 `presentation`；资源版本标签、执行摘要、制品身份保持明确。 |
| Group/Compliance | name/description（Group）和 name（Compliance）位于 `presentation`。 |
| 证书档案 | `metadata` 保留原描述键并允许有界未知 key；owner/usages 是说明，不是可信主体或证书用途证明。 |
| Webhook 设置 | name 位于 `presentation`；目标、密钥与投递状态保持明确。 |

完整对象编辑须将未知 key 原样带回，省略即删除；不支持旧平铺路径或隐式合并。
普通扩展对象默认 64 KiB、深度 16、4096 节点，证书及现有请求/存储的更严格预算优先。
原生采集 rows 和 FieldValue 保留批准查询返回的额外普通属性，新增结果属性不扩大 recipe/scope。
已声明属性、实例键、完整性证据及敏感材料禁入规则仍校验；只有字典和冻结 mapping 接纳的
内容进入可信资产。原始未知属性按敏感证据保存，不能自动进入 Group/Compliance 或普通读取。
普通报告保留完整规范内容用于幂等，投影摘要只绑定可信输出；Native 继续使用原有内联/chunk
和完整内容摘要。扩展 key 不改变全局协议版本，schema 指纹只标识实际生成制品。

Agent/Web 从最终固定公开 rev 一次切换；此处不要求读取服务端私有 checkout。

遥测 Profile 只引用 Inventory 的精确字段键和版本；发布组合层解析并冻结该版本，后续配置与已接收批次继续使用原定义。历史 Counter 的 `missing`/`failed` 同样携带真实 `intervalStart`，结构化读数通过 `context` 提供稳定资源键、有限维度和声明路径上的区间起点。`context` 不产生有效数值；必要上下文未知时拒绝该历史输入，不按接收时间伪造起点，也不静默删除质量事实。

## Agent 企业登录与当前使用者

Agent 登录使用现有后端 Identity 用户；设备绑定入口是 `GET/PUT/DELETE /api/v1/agent/runtime/current-user`。三个方法均要求当前有效设备 mTLS，PUT 还必须携带已有 `x-rss-user-session` 企业会话。PUT/DELETE 的请求与响应类型由 [当前 wire 源码](../../crates/agent-wire/src/current_user.rs) 和其生成 schema 唯一持有，使用稳定 operationId 与 GET 返回的 expectedRevision。客户端不能提交 user、device、tenant 或 SessionReference 来声明身份；仅库存能力的已注册 Agent 也可使用此入口。

PUT 显式登录或切换当前用户，并在同一事务中填充仍为空的资产所有人；DELETE 使用设备身份和 CAS 退出，不依赖尚未过期的企业会话。未知结果保留原 operationId 和输入，精确重放返回原回执，不再次填充所有人；旧 revision 不能覆盖新登录或退出新用户。读取在释放设备事务后重新核验保留会话，再用短事务确认设备有效性和绑定 revision；核验期间发生切换或退出时返回 409，客户端应重新读取。失效返回 invalidated，Identity 依赖故障返回不可用。confirmedAt 是服务器上次确认时间，active 表示会话有效，不证明设备在线。

此合同只保存不可用于认证的可信 SessionReference，不保存企业会话秘密或复制人员目录。桌面/Agent 后续需在登录、切换和退出生命周期接入这些端点；后台不会从普通网站登录或 OS 用户观察猜测设备当前使用者。


## Device Access 账号关联与应用

`device_access.v1` 是独立原生能力。首次开通使用设备认证与 `x-rss-user-session` 的真实 RSS 会话，
先通过 `GET /api/v1/agent/runtime/device-access` 查询可开通 Policy 及本人绑定（使用 `limit/cursor`，响应 `nextCursor` 为绑定设备注册、本人会话与权限的签名游标；按 Policy ID 实时扫描资格，空候选页也按 nextCursor 继续，不支持 filter/sort/fields），
再依次调用 `/api/v1/agent/runtime/device-access/begin` 和 `/confirm`。Begin 只选择已分配的 Policy，
不接受 principal 或本地账号；返回 120 秒挑战及当前交互会话。Agent 必须从受保护的本机 broker
重新核验本地账号、SID/GeneratedUID、会话及本地账号来源，再确认。Windows account 必须携带 authority：local、active_directory（domainSid）或 entra（tenantId/objectId），交互上下文 windowsAuthority 与账号来源一致；Mac 上该字段为 null。来源必须由原生安全上下文建立，不能根据用户名、UPN 或 SID 外形猜测。MSA 与 RDP 不在当前范围。
普通进程上报、软件清单和最近登录记录不能替代该核验。用户名仅用于显示或新建目标，不能接管同名账号。

首次开通只用于尚未建立 Device Access 关联的当前注册；之后由 RSS 后台管理员修改或新增。
Begin/confirm 在宿主同一 READ COMMITTED 写事务内调用 Identity 的 live-session 准入，先取得 Identity guard，再取得注册和业务锁；会话撤销与绑定提交串行化。原会话过期仍然生效，此准入不续期、不消费 step-up。
确认使用稳定 operationId；响应丢失重试原请求，不换 nonce 或账号。Begin 的 nonce 不入库存储，
响应丢失后重新发起新 ceremony；并发 ceremony 仍只有一个能够完成首次关联。
每设备每注册最多保留 128 个绑定记录及 128 个未清理 ceremony，失效绑定保留，过期未消费 ceremony 可清理。

签名 `device_access` task 复用 Offer/Received/Start，包含人员、注册/绑定代际、配置 revision 和摘要。
收到 Offer 不能执行；Start 前重新核验目标、权限及本机条件。Create 的系统密码只经本机交互设置，
同名冲突必须失败，不能自动关联现有账号。Unbind 明确携带 disposition（keep/disable/standard）；保留数据，按原意图保留、禁用账号或移除管理员权限，结果 unbound 必须携带同一 disposition。
收到/实际应用分别上报；`device_access_result` 的 Mac 结果携带系统 PSSO 配置/注册观察、注册来源、Secure Token、卷所有权和 FileVault 解锁资格。Password 完成要求当前原生配置和设备/用户注册已确认；密码与登录钥匙串同步由 macOS 执行，接口不报告独立同步结果。FileVault 强化还须确认卷所有权与解锁资格。安全限制（最后管理员/恢复账号）失败使用闭合错误类别。

Windows RSS 附加因子首次开通和显式因子重置在同一个 Device Access task 内完成：本机交互准备 TOTP 和新账号密码后才 Start，
以 `device_access_prepared` 报告真实 SID（尚非 Applied），再用既有加密 escrow 托管恢复材料。
托管 ACK 的材料 ID/version 与签名任务的 factorGeneration 一起用于本机原子激活及读回，最终 Applied 必须回报这些精确坐标。
中断后重放同一任务与候选，未决材料不能通过失败或取消回执丢弃。普通配置 revision 不重置因子；
配置失败观察也不抹去最后已验证的因子事实。

WHfB 需要 `device_access.v1` 与 `device_access.whfb.v1`，使用同一任务的 `windows.kind=whfb` 分支；不准备 TOTP、不托管 RSS 恢复材料、不要求 RSS CP。`previousKey` 是因子重置前已观察的原生 key ID；旧 key 不能作为新代际的注册完成证明。`effect.windows.kind=whfb` 分别报告策略、注册、TPM 凭据与 UTC 观察时间，并绑定 Entra tenant/object ID。配置存在不能证明登录成功。未知观察保持待完成。

解绑任务的 `retire=true` 停止注册并核对凭据清理，结果为 `whfb_retired`；只有策略和注册均确认不存在且账号处置匹配时才完成。停止注册不删除已有凭据，目录撤销及已登录会话是独立生命周期事实。PIN 恢复由 Windows/Entra 执行，RSS 恢复材料不能用于 Hello。当前合同只证明服务端处理，Windows 原生调用、签名和真机均未验证。

Windows RSS 恢复后续轮换/核对使用既有 Credential task 的 `rotate_rss_login`/`verify_rss_login` 和加密 escrow，
每账号绑定及代际独立。材料是 CSPRNG 生成的 32 字节、规范无填充 base64url 编码；
没有到期或一次性消费语义。托管确认后才能原子替换本机 verifier，旧版保留至实际应用确认。
`/device-access/recovery-uses` 接收无秘密的离线使用事实，operationId 去重；每个材料 entry 最多 4096 条事实，
满额拒绝新的补报但不使本机密钥失效。使用时间和服务端接收时间独立。

本后端契约不证明 Agent、Windows CP 或 Apple PSSO 的真实执行；对应消费和平台证据由 #2870–#2876 承接。

平台 verifier 的 resolve/recheck 必须在 Identity 提供的原 PG connection 上调用
`ExecutionService::active_access_binding_on`，同时核对当前注册、绑定代际和 Policy/Scope。
普通 Binding JSON、清单或历史状态不能作为有效会话证明；Identity 继续独占账户/成员有效性与会话签发。

## 管理目录查询

`GET /api/v1/agent-configurations` 返回 `items/nextCursor` 元数据页，使用
`filter/sort/fields/limit/cursor`，默认 64、最多 1000 条。可按 state、创建/到期时间、创建者及目标平台筛选；
平台/架构是目标集合成员条件，不用于排序。createdAt/expiresAt 使用 UTC Unix 秒。
列表与详情共用配置身份和 available/expired/revoked 状态规则；remaining 只代表数量。
列表不返回 secret、签名、连接配置或可转移配置文件，也不提供原地修改签名配置的入口。

`GET /api/v1/agent-packages` 使用同一分页契约，管理者可查询 published/withdrawn 元数据；
`GET /api/v1/agent-packages/{id}` 读取同一元数据对象。管理目录可见不代表当前可安装。
`/api/v1/agent/enroll/packages` 及下载协议保持原数组/准入行为，只向公共消费者开放当前可用包。
本批后端直接替换旧管理列表数组，前端消费者需另行同步。


## 受控企业 RP 的 Broker 协议

跨进程输入由 `rss-mdm-agent-wire::enterprise` 持有。先同源 POST
`/api/v1/device-access/broker/browser` 建立 Secure/HttpOnly/SameSite=Strict 的浏览器绑定，
再 POST `/api/v1/device-access/broker`，提交 `{operationId,bindingId,relyingParty}`。
客户端不选择回调、受众或身份；返回确切 `signingPayload`，原生 Broker 必须原样签署，
不能重新编码 JSON。Windows 使用管理员已登记、绑定确切账户/因子代际的 P-256 key；
Mac 使用当前 SE 用户 key，Password 模式使用设备 key，并提供有效原生 accessToken。
这些证明只证明持钥和已验证凭据，不代表用户在场、UV 或 MFA。

POST `/broker/complete` 使用 `{operationId,challengeId,nonce,proof:{signature,accessToken}}`，
signature 为无填充 base64url 的 64 字节 ES256 签名，Windows 的 accessToken 为 null。
服务端只在后台交换 Identity assertion；浏览器 Ready 响应只含固定 callback 和 continuation。
GET `/broker/{operationId}` 与 POST `/broker/{operationId}/cancel` 都要求原浏览器绑定和精确 Origin。
Preparing/Completing 中断须查询原 operation；120 秒准备窗口或原始挑战截止后状态过期/未知，
不得重放可能已完成的 IdP 交换。取消后旧 continuation 和 RP 会话查询均拒绝。

每个 RP 后端使用独立部署 bearer secret，POST
`/api/v1/device-access/relying-parties/{rp}/consume`，提交 `{session:operationId,operationId:领取操作UUID,continuation}`。
同一领取操作可以恢复回执，但每次秘密释放都重新联合核验 Identity 会话、RP 配置、稳定人员映射、
绑定和原生会话；其他 RP 或其他领取操作不能冒领。交接只在上游令牌最多 30 秒的窗口内有效。
RP 自己建立应用会话，每次使用前调用 GET `/relying-parties/{rp}/sessions/{session}` 复核。
该 session 是产品业务定位符，不能用于 Identity 登录。当前交付互操作范围为受控 `rp-a`、`rp-b`，
不声明任意外部应用或独立 Agent 已完成接入。


### 独立 FileVault CMS 托管

Agent runtime 的 `GET /filevault/configuration` 返回当前设备的采集授权与公开收件证书；默认关闭。
管理者通过设备恢复凭据的 `GET filevault/configuration` 读取当前配置，再以 `POST` 显式授权，提供当前注册代际、配置 revision、收件证书指纹及幂等 operation；并发修改冲突后重新读取。多个有效来源时必须指定注册及代际。
端上系统服务只读 Apple 生成的 `/var/db/FileVaultPRK.dat`，通过 `POST /filevault/escrows` 上传原始 CMS；
`GET /filevault/operations/{id}` 恢复未知提交结果。此路径不依赖普通任务或 MDM 注册，不接收员工 bearer、任意文件路径或目标 URL。
文件缺失或证书不匹配必须等待合法平台材料，采集不能自动安装 profile、生成/轮换 PRK 或改变账号密码。

FileVault 托管身份独立于采集通道；MDM 与 Agent 可以分别使用。同一设备已验证关联后，具有两侧安全操作权限的管理者
可使用 `filevault/link` 明确关联来源，以请求目标设备的 custody 为保留归属。共享来源绑定此次设备关联及版本；关联撤销后立即失去共享访问与新上传权限。单通道退役保留仍有效来源的托管能力。待决轮换和收件人冲突会阻止归并；不按序列号或相同密文自动归并。
托管回执仅证明材料已受保护保存，不能证明它是当前可用于恢复解锁的密钥。普通诊断不返回 PRK 或 CMS。

## 设备管理活动

Agent 使用设备证书读取 `GET /api/v1/agent/runtime/management-activities`、
`GET /api/v1/agent/runtime/management-activities/{id}` 和
`GET /api/v1/agent/runtime/management-activities/changes`。读取不要求任务执行 capability，也不会触发领取、重试或执行。
管理端对应 `GET /api/v1/devices/{device}/management-activities` 及其 `/{id}`，逐设备要求 `OperationRead`。
跨 Agent／MDM 通道仅使用当前已验证的逻辑设备配对；配对尚未发布时只返回本端点并标记 `association_pending`。

列表默认 50、最多 200 条，使用 `limit/cursor`；可选 `from/until/source/kind/status/policy/request/batch/task/operation`。
时间范围为 UTC Unix 秒，`from` 包含、`until` 不包含。`status` 匹配实际记录的 delivery、execution、effect、reporting 或 decision。
`items` 是允许字段组成的摘要，不含执行输出、参数、凭据、人员身份或 OS 账户标识；允许看到本设备其他人的活动摘要。
每条保留当时的阶段与准确业务引用，步骤标识使用发布定义中的 step ID，并由 task 和 attempt 限定。
执行完成、效果已验证、结果已接收和审计事务成功是不同字段，不能互相替代。

个人列表及详情使用 `view=personal`，同时提供 `x-rss-user-session`。服务端校验当前企业会话、设备当前用户绑定和 OS 身份；
相同企业主体与稳定 OS 身份可读取先前登录会话中属于自己的活动。注销、换用户、重新注册或配对变化会使旧游标失效。
个人视图仍不返回原始输出或秘密。详情关联只包含当前授权范围内的事实及其确切 Policy 版本父事实，不能据此读取该 Policy 的其他设备。
详情的 `relatedCursor` 继续使用列表入口，并保留对应 task／operation／batch 等过滤条件和个人视图条件；
`policy_history_truncated` 表示该详情的 Policy 父事实超过 50 条，不表示完整历史。

先消费列表全部 `nextCursor` 页面，再以 `syncCursor` 调用 `/changes`。历史页面冻结各设备的发布水位；
增量按事务提交后的发布修订读取，客户端按活动 `id` 去重。来源审计序号不作为增量提交水位，晚提交的低序号记录仍可发现。
增量存在 `nextCursor` 时先读完该轮；末页以新的 `syncCursor` 继续。游标必须原样使用，保持过滤与视图；允许改变合法页大小。
签名、读取范围、注册世代或投影世代不匹配返回 409 `activity_cursor_invalidated`，客户端清除该范围游标并重新读取首页。
活动不存在或不在可见范围返回 404 `activity_not_found`。

响应 `asOf` 为服务端观察时间，`coverage` 表示该观察时刻的投影覆盖；请求每次最多补齐 64 条、8 MiB 来源事实。
来源仍有未投影事实时保守返回 `source_catchup_pending`，不能把空页理解为没有活动。
`retainedFrom` 只计算当前授权注册范围内的已保留事实；本入口不新增清理任务，也不承诺客户端离线副本的新鲜度。
读取和缓存展示必须保留这些字段。活动只消费生产者明确记录的结构化事实，不把旧式审计记录或当前业务状态重建为历史阶段。
