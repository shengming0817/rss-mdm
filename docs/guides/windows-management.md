# Windows 原生管理

原生采集在设备请求中持久记录签入，由后台逐项准备和恢复；新触发的采集可在后续签入下发。
积压期间保留进行中的策略扫描，并合并为一个最新待处理签入，不补跑全部历史签入。
重启从已提交进度继续；当前回执和实际投递仍即时校验授权与注册世代。

部署网关终止注册 HTTPS 与管理 mTLS，后端只接受受信网关覆盖的 TLS 证据并独立验证设备身份。先按 [注册指南](device-enrollment.md) 创建 mdm.windows 授权并分发口令。Discovery、Policy、Enrollment.svc 与 MDM.svc 使用配置的精确 origin，Host/To 必须一致；设备须预先信任服务 TLS 根。首注 enrollment origin 不请求客户端证书；management、Agent 和 Apple 的证书入口必须使用其它 origin，可共用主机名并分离端口。配置拒绝这两类入口重叠。

## 证书与会话

Windows 使用固定版本 step-ca，宿主只加载公开 `trust_file` 与受保护的 JWK provisioner 凭据，不加载 CA 根或中间签名私钥。CA 代次由 `device_pki` 显式配置；TLS 与协议保护密钥分别管理，并与数据库一起保护和备份。issuer 通过受控信任轮换切换；改变协议保护密钥或稳定注册配置须走明确恢复/重新注册流程。

Windows UsernameToken 只接受 `<enrollmentId>@<注册 origin 的主机名>` 与一次性口令，主机名不含端口；纯 UUID、错误域和非规范 UUID 均拒绝。从注册详情的 `instructions.username` 复制该值。用户以本机管理员身份打开“设置 → 账户 → 访问工作或学校 → 连接 → 仅注册到设备管理”，输入用户名、口令及详情提供的注册服务器；Full／Device 必须与授权一致。Discovery 支持无响应体的 GET／HEAD 连通性探测和原生 SOAP POST。签发期间持续核对原管理员授权，最终绑定提交后证书才可准入。响应丢失沿原意图恢复；重启后由原管理员重新登录、resume。证书安装位置及 Full/Device 注册须在对应 Windows 版本上单独验收，EntDMID 不能替代 mTLS 身份。

管理会话同时校验证书链、用途、当前凭据映射与 SyncML 认证。采用 APPSRV BASIC / CLIENT DIGEST；会话绑定注册世代、证书与消息关联，精确重传返回原响应，异内容冲突。被替代会话不能继续推进。撤销后，每次请求立即通过当前凭据映射拒绝，包括保留连接上的后续请求。缺少、回滚或过期的签名 CRL 同样拒绝认证。Full 用户任务的 `NativeTarget.User.userId` 必须等于当前注册的 `userContextId`，创建、投递和回执都重新核对。会话初始 LoginStatus.User 只表示该已认证会话的用户可用；None、Others 或缺失时用户任务等待，设备任务仍可执行。续期保持注册与用户上下文，重新注册生成新的上下文，旧标识不能沿用。

会话以加密的原始请求和实际响应记录为唯一关联来源，重启后按 MsgID 连续重建；没有另存的关联缓存。当前预算为最多 128 条消息、每条 XML 512 KiB、编码对象 16 MiB、解码对象 12 MiB；响应还受设备声明的 MaxMsgSize / MaxObjSize 限制。非 Final 包仅积累回执，完整 Final 与当前授权共同决定成功结算。

命令数和 XML 结构预算属于本地资源防护，不代表 Windows 协议上限。Windows 忽略 SyncHdr/Meta，因此服务端不依赖该字段约束客户端回复；下发前同时为 Get 的 Status 与 Results、逐项回执和组合命令回执预留接收容量，超出时保留未发步骤到后续消息。成功 Results 不再额外回复 Status 200，遵循 OMA DM Representation Protocol §6.5.1。

Get Results 的 MoreData / Size 在连续消息中重组，最后一片通过大小、引用与授权核对后才形成值。单 Item Add/Replace 可按实际 XML 字节分片；每片范围留在原 attempt，213 只允许继续传输，最后一片的成功回执才代表对象交付。Atomic/Sequence 保持整体，不跨包拆分。中断、大小冲突及预算耗尽关闭传输并保留未知结果；Abort 和非 Final 预算耗尽将未完成采集分别以 aborted / message_budget 失败结束，不投递成功快照，沿既有恢复 owner 处理，不盲目重发有副作用的命令。

1226 Generic Alert 保存原生类型、源 URI 和不可逆证据摘要并原样关联 ACK；1222 / 1223 / 1225 仅控制协议传输。通知与交付回执不证明业务效果，也不提供应用 Correlator 支持。

真实 TCP peer 承担连接/速率限制，NAT 后设备可能共享预算；接入拒绝不放大数据库审计。过期临时会话可清理，凭据、签发与审计事实仍保留。协议字段及预算由 [codec](../../crates/windows-mdm/src) 与 [Windows 通道](../../crates/windows-channel/src) 持有；原始样本来源见 [fixtures](../../crates/windows-mdm/tests/fixtures/README.md)。

## 用户任务与配置输入

用户配置通过 Resource 的 NativeConfiguration 内容和 Policy 消费。有权管理员从 `GET /api/v1/devices/{device}/registrations` 的 Full 活动注册读取 `userContextId`，将其用于配置的 `target.kind="user"`；`apply` / `remove` 属于当前注册的用户 scope。Policy 冻结资源版本，配置示例如下：

```json
{"target":{"kind":"user","userId":"<当前 Full 注册的 userContextId>"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./User/Vendor/MSFT/Policy/Config/Experience/AllowThirdPartySuggestionsInWindowsSpotlight","instance":[],"operation":"replace","value":{"type":"integer","value":"1"}}}},"remove":null}
```

## 通道配置与维护

`windows.poll` 是必填的八字段配置，分钟单位；完整示例见 [配置样本](../../fixtures/mdm-config.example.json)。样本先每 15 分钟尝试 10 次，禁用第二阶段，然后每天无限轮询；两项登录触发均为 false。配置必须有可到达的无限阶段，不能依赖 Windows 对无效配置的自动修正。注册 provisioning 消费这个完整类型。内部原生编译器 `rss_mdm_windows_mdm::native::Request::poll_schedule(provider_id, &poll)` 保留完整 Poll Replace Sequence 与 readback 规则，部分写入、删除和类型错误被拒绝。设备控制入口不提供 Poll 维护，也不接受任意 SyncML Sequence；不存在可提交的旧 operation envelope。

WNS 可选。配置 `push.package_family_name`、`sid` 和受保护的 `client_secret_file`；通道向当前已认证设备读取并关联 PFN / ChannelURI。只接受配置 PFN 与 HTTPS notify.windows.com 路由，不跟随重定向。URL 加密保存，token 仅内存缓存。worker 在审计事务内按当前注册世代、来源、凭据及任务授权获取租约，提交后发送空的 wns/raw 唤醒，再按世代、路由版本和租约结算。Accepted 仅为 WNS 接收，Unknown 表示网络结果不确定，两者均不能证明设备签入、命令交付或效果；Poll 独立继续工作。重复观察同一 URL 只刷新有效期，不重置租约或终止结果，URL 改变才增加版本。

内部原生 DMClient / DMAcc 维护规则保留在通道 owner 中，设备控制入口不提供这些维护操作。DMClient 维护限定当前 provider。DMAcc 先读取所选 account 的 ServerID，证实当前 provider 后才执行账户操作。管理地址修改只能指向配置的主地址或 `additional_management` 中真实启用的独立监听地址；Host、绝对 HTTP URI authority 与 SyncML Target 必须对应实际 listener。效果需另一个会话连接到所需实际地址，并提供关联 readback，客户端自报 Source 不能替代重连证据。

## 续期与原生注销

首次 provisioning 的 CertificateStore/My/WSTEP/Renew/ServerURL 指向 management origin 的 Discovery.svc；它要求当前证书并返回 Certificate 策略。续期在该 origin 的 Policy.svc / Enrollment.svc 上使用原 TLS 叶证书、签名 CMS PKCS#7 与新 CSR。首注入口拒绝续期，证书入口拒绝主登记的初始 PKCS#10。只接受当前证书对应的当前注册及允许的续期窗口；响应可沿原材料精确恢复。签发新证书后旧凭据仍有效，直到新证书首次通过管理 mTLS 证明持有，才在事务内激活新凭据、替代旧凭据。续期不创建新设备、注册或协议账户。

原生 `com.microsoft:mdm.unenrollment.userrequest` 在原事务内退休注册、凭据、执行参与方、采集、push 与活动会话，并保存独立加密回执。并发或丢失响应重试得到相同字节；回执不依赖临时会话保留。退休证书只能恢复这份精确历史请求的回执，不能构造 active principal 或继续接收新工作。服务器退休不能证明终端已清理管理账户，审计中的设备清理状态保持 unverified。

普通 Full 用户注册不依赖组织联合身份。WinDC 子登记走证书式协议：management origin 的 `/EnrollmentConfiguration?api-version=1.0` 只接受 `enrollmentType="User"`，返回 Certificate 策略与独立 LinkedPolicy.svc / LinkedEnrollment.svc。发现字段不建立组织身份；未支持的 Federated/Entra JWT 流程拒绝。

XCEP 仅返回策略，导出的 BST 不授予登记权限。LinkedEnrollment.svc 校验原始 XML 的父证书签名、时间戳、当前父凭据及新 CSR 私钥证明，签发独立子证书。子登记与父登记共享设备身份，使用独立 provider、证书、世代、命令编号和 `/ManagementServer/Declared.svc` 会话；首次真正认证签入后才能接受任务。子登记不建立 Inventory 报告源。父证书正常续期保留子登记；父重新登记、撤销或被替换会连带退役子登记。子证书通过 management origin 的 LinkedDiscovery.svc 发现自己的登记入口续期，父子证书不能跨管理入口使用。

WinDC 子登记缺失或尚未首次认证时，Declared 配置策略保留等待状态和既有资源占用，并返回 `windows_declared_enrollment_not_ready` 诊断。先完成子登记及 Declared 首次认证签入；首次认证会唤醒等待配置。普通主登记和 ConfigRefresh 独立可用。

## DeclaredConfiguration 与 MI

DeclaredConfiguration 使用 Resource / Policy 配置入口，Document 值为原生 XML；Delete 输入也保留原始文档，供删除效果与资源占用确认。支持的 Windows 证书协议版本来自冻结的官方事实，未知 servicing 分支拒绝。普通 ConfigRefresh 继续使用主登记。

CSP 文档按内容检查每个资源的既有权限、schema 与设备能力。MI 参数的键和值均为字符串，仅允许 Device scope，并独立要求设备范围的 `windows_mi_execute` 权限。系统不维护 MI provider 白名单；资源占用按规范化 namespace/class 整类隔离，同一文档不重复声明同类，Key/Value 角色分别保留。

1224 摘要仅触发匹配文档的完整 Results 查询。操作须核对文档 GUID、scope、版本、操作和全部资源的终态，SyncML ACK、摘要及 404 均不能证明完成。异步观察复用既有 attempt 与恢复流程；删除确认完成后才释放占用。删除 RefreshInterval 后按协议默认 240 分钟确认。

## 采集与恢复

CollectionRun 拥有命令关联、完整性与报告封存。Status 或 Final 单独不能证明完成；成功 Status 加关联 Results 才提供字段事实。明确 501 可表明 Unsupported，404/500、超时、缺失不能推断为不支持。所有字段成功或明确不支持才形成完整 Snapshot；Partial/Failed 保留最后完整资产，无字段结果不伪造 Observation。

报告使用稳定 sequence/batch/scope，接收时间用于来源证据。提交未知沿原身份恢复，不能因查询暂时缺失而删除旧资产。报告 durable 与资产投影分别查询；后台故障拒绝健康声明。统一资产不要求调用者选择来源，详见 [资产指南](assets.md)。

配置与升级见 [安装](../deployment/installation.md) 和 [运维](../deployment/operations.md)。受控 TLS/SyncML 测试仅证明服务端接缝；真实设备支持矩阵与证书安装、首次签入和采集闭环须由产品 T3 给出。

协议依据：[DMClient CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/dmclient-csp)、[Microsoft OMA DM](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support)、[w7 APPLICATION CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/w7-application-csp)、[RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.html#section-5)。

## 设备信任轮换

服务端在已有认证 SyncML 会话中通过 RootCATrustedCertificates CSP 安装完整重叠集合：根进入 Device/Root，中间证书进入 Device/CA。SHA1 只用作 Windows CSP 节点定位；代次、安装回执与证书身份使用 SHA256。每条证书均以关联的 Get 回读 exact DER 确认，分条投递遵守设备消息预算；Add 的成功状态不能代替安装证明。安装完成后才记录对应 trust revision 的回执，管理员取得必需设备回执后可一次激活新 issuer。旧 CA 退役后删除其 CSP 节点，并用关联 Get 的 404 确认移除。注册、代际、证书、会话与消息关联继续由原 owner 校验。

签发默认完整 90 天，冻结 CSR/SPKI、注册 CN、issuer 与绝对有效期后才调用 CA；初始、关联注册与续期共用该路径。未知结果只能找回原 CA 的原证书，不重复签发。迁移与管理接口见[安装](../deployment/installation.md#设备-pki-升级)和[运维](../deployment/operations.md#设备-pki-轮换与撤销)。真实 Windows 的 Root/CA 安装、续期和退役需要独立 T3 证据。

## 私有 Entra 原生注册

每个客户部署只绑定一个客户 Entra tenant 和其内部 MDM 应用。`native_protocols.windows.entra` 为可选的严格配置：`provider_id` 指向 Identity 已启用的 Entra provider；`native_callbacks` 是部署允许的完整原生回调 URI 列表（HTTPS 或 ms-appx-web，不含查询参数）；`token` 包含 `tenant`、`app_id`、`authorized_clients`、非空 `required_scopes` 和明确的 `device_claim`。Identity provider 的 subject 必须为 `{"kind":"entra","tenant":"客户 tenant UUID"}`，issuer 固定为该租户的 Microsoft v2 issuer，浏览器 scopes 包含 openid、profile。JIT 由 Identity 独立、明确配置，默认禁用；MDM 组织策略不会打开 JIT。浏览器与原生人员身份均使用同一 provider 的 `(tid,oid)`，不使用 sub、email 或 UPN 兜底。

Access token 只接受 Entra v2、RS256、appId audience、明确允许的客户端与 delegated scopes、`idtyp=user`，并验证签名、issuer 和时间。应用需配置 include_user_token optional claim。实际 WSTEP 注册必须有非空设备 UUID claim；TOU 阶段允许缺少该 claim。Token 不创建浏览器会话，也不充当设备证书；续证与管理仍使用已建立的设备证书和现有协议认证。

`GET /api/v1/windows/entra-policy` 与 `PUT` 使用产品管理认证及 registration_configuration_read／registration_configuration_write；写入包含 `expectedRevision`、`operationId` 和 `policy`。策略字段为 enabled、allUsers、users（明确的 oid 列表）、termsVersion、termsText（最多 32768 字节的纯文本）、allowBackground。缺少策略时默认关闭；组织用户范围、条款版本和非交互注册授权均由 MDM 持有。没有 Graph 查询或隐式 group/scope 推断。

产品浏览器 HTTPS origin 提供 `GET /api/v1/windows/entra/terms` 原生入口。Windows 在 Authorization 中传入 Entra Bearer token，查询包含 redirect_uri、client-request-id、api-version=1.0；组织加入另带 mode=azureadjoin。入口校验完整回调 allowlist、token 和当前策略后设置 Secure／HttpOnly 的短期流程 cookie，并重定向到同源 `/enrollment/windows/entra/terms`。注册监听器不再提供旧的 JSON 条款 GET／POST。

页面通过 `GET /api/v1/windows/entra/terms/context` 获取 termsText、termsVersion、mode、canDecline、csrfToken、expiresAt（Unix 秒），以原生表单 `POST /api/v1/windows/entra/terms/finish` 提交 csrfToken 和 accepted。finish 必须有精确产品 Origin；组织加入禁止拒绝。服务端重新验证 token、策略范围、revision 与版本，302 回到原生 URI，携带 IsAccepted、接受时的 OpaqueBlob 与 client-request-id；相同决定重试返回同一回调，相反决定冲突。页面无需 RSS 登录，不接触 token 或 opaque。Windows 11 可在原生 iframe 内展示页面：部署仅为此 TOU 页面配置精确的原生 frame origin allowlist，其余页面保持禁止嵌入。

流程令牌和 opaque 通过现有 native-protection 加密持久化，可跨实例和重启继续；最长五分钟且不超过 JWT 到期。条款文本变化必须使用新 termsVersion，CAS revision 的变化使旧流程失效。当前安装清单不提供旧库兼容升级：旧安装须按[安装契约](../deployment/installation.md)重新安装，并重新配置条款及组织策略。SQL 单元对既有策略的处理不构成独立升级入口；管理员须填入新条款后明确启用。同意记录绑定 tid、oid、策略 revision 与同一截止时间；原生 WSTEP 将 OpaqueBlob 放入 EnrollmentData。首次消费绑定一个注册请求及其 CSR／profile，精确重试复用该结果；其它用户、设备或输入不能重用。未携带同意时只有明确启用 allowBackground 的组织策略可以授权用户凭据注册。

原生准入先验证 token 和 MDM 范围、设备及同意，再由 Identity 解析／JIT canonical 账户。它使用独立 windows_entra authority_kind，不持有密码或浏览器会话续接引用；设备身份为 `entra:{tid}:{deviceid}`，客户端 DeviceID 仅是协议描述输入。签发复用同一持久 PKI 意图、回执和设备绑定流程，最终绑定前在无 MDM 锁时重验 Identity，然后在 MDM 事务内重验组织策略。注册期间的撤销或策略版本变化会拒绝完成。

Entra 用户凭据注册保留 canonical 注册用户及组织来源，按 WMD-E06 免个人 Windows MDM 额度，不伪装为 self_service；个人额度为零也不阻止已获组织策略及同意授权的注册。设备归属、组织策略、同意和世代校验仍由共享原生生命周期执行。

本项提供原生 TOU 续接协议与组织配置后端，Web 页面与安装引导由 #2633 完成。合成签名／JWKS、真实 HTTPS／PG 的 T2 不证明真实 Entra 或 Windows 注册通过：Settings／OOBE 验收见 #2690，AD／hybrid GPO 第三方兼容性见 #2691；当前只接受用户凭据，不提供 Device Credential、Autopilot 或 Graph compliance。

协议依据：[Microsoft Entra 与 MDM 集成](https://learn.microsoft.com/en-us/windows/client-management/azure-active-directory-integration-with-mdm)、[Access-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)、[Optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)。Entra 注册使用系统提供的 discovery 地址并跳过 AuthenticationServiceURL；配置 Entra 后 Discovery 明确返回 Federated。生产 verifier 的密钥来源固定为客户租户的 Microsoft 公共 JWKS，不接受自定义 URL、重定向或代理。

## 原生资产采集

Windows 标准蓝图版本为 `2`，通过普通 Resource 实例化并绑定 `native_collection` Policy。声明使用 `windows_read`；标量 query 为 `{"kind":"scalar","uri":"./DevInfo/Mod"}`，动态清单为 `{"kind":"inventory","inventory":"win32"}`。注册 ID/type 使用 `enrollment_id` / `enrollment_type`，执行时只绑定当前 provider。旧 Windows adapter、字符串 query 和旧蓝图版本拒绝；存储修订随当前安装基线切换，不提供旧库双读或就地迁移。

以下均为 Device 范围、Primary 注册、CSP Get。表中 build 是模板准入下限，执行同时核对固定 schema 的每个节点和 edition；缺少可信 build/edition 时不派发。下表是声明支持面，不是真机测试矩阵：受控样本以 Windows 11 Pro 22621 为上下文；真实 OS、SKU、注册方式验收由产品 T3 单独提供。Win32 文档仅声明 Windows 10/11，10240 是 OS 家族下限，不承诺该早期构建的真机支持。Win32 当前准入 Pro/Pro N、Enterprise/Enterprise N、Education/Education N、IoT Enterprise；Update 还允许 Home/Core N 和 SE。其它 CSP 使用固定 DDF 的 edition 集合。

每行链接提供原始受控 SyncML Results 样本；同目录同名 `.json` 是独立预期归一化值。样本不是设备抓包，完整会话、状态关联与重试由协议测试和 `windows.management` T2 验证。字段列也给出资产/Group 消费示例：标量可按字段等值比较，数组可按其 `.id` 使用 `contains_any`；具体期望值见 JSON，不能用跨数组属性 AND 冒充同条目关联。

| 蓝图（省略 windows.） | 最低 build | 官方来源 | 样本 | 查询字段示例 |
|---|---:|---|---|---|
| `hardware` | 10586 | [devdetail](https://learn.microsoft.com/en-us/windows/client-management/mdm/devdetail-csp) | [XML](../../fixtures/windows-collection/hardware.xml) / [JSON](../../fixtures/windows-collection/hardware.json) | `device.model` |
| `hardware.network` | 10586 | [devicestatus](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp) | [XML](../../fixtures/windows-collection/hardware.network.xml) / [JSON](../../fixtures/windows-collection/hardware.network.json) | `device.network.windows.identifiers.id` |
| `hardware.serial` | 17763 | [devdetail](https://learn.microsoft.com/en-us/windows/client-management/mdm/devdetail-csp) | [XML](../../fixtures/windows-collection/hardware.serial.xml) / [JSON](../../fixtures/windows-collection/hardware.serial.json) | `device.serial_number` |
| `identity.edition` | 15063 | [devicestatus](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp) | [XML](../../fixtures/windows-collection/identity.edition.xml) / [JSON](../../fixtures/windows-collection/identity.edition.json) | `device.os.edition` |
| `identity` | 10586 | [devdetail](https://learn.microsoft.com/en-us/windows/client-management/mdm/devdetail-csp) | [XML](../../fixtures/windows-collection/identity.xml) / [JSON](../../fixtures/windows-collection/identity.json) | `device.os.version` |
| `management.domain` | 17134 | [devicestatus](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp) | [XML](../../fixtures/windows-collection/management.domain.xml) / [JSON](../../fixtures/windows-collection/management.domain.json) | `device.management.windows.domain_name` |
| `management` | 14393 | [dmclient](https://learn.microsoft.com/en-us/windows/client-management/mdm/dmclient-csp) | [XML](../../fixtures/windows-collection/management.xml) / [JSON](../../fixtures/windows-collection/management.json) | `device.management.windows.enrollment_id` |
| `security.antivirus` | 15063 | [devicestatus](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp) | [XML](../../fixtures/windows-collection/security.antivirus.xml) / [JSON](../../fixtures/windows-collection/security.antivirus.json) | `device.security.windows.antivirus.status` |
| `security.bitlocker` | 18362 | [bitlocker](https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp) | [XML](../../fixtures/windows-collection/security.bitlocker.xml) / [JSON](../../fixtures/windows-collection/security.bitlocker.json) | `device.security.windows.bitlocker.compliance_errors` |
| `security.defender` | 15063 | [defender](https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp) | [XML](../../fixtures/windows-collection/security.defender.xml) / [JSON](../../fixtures/windows-collection/security.defender.json) | `device.security.windows.defender.enabled` |
| `security.device_guard` | 17134 | [devicestatus](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp) | [XML](../../fixtures/windows-collection/security.device_guard.xml) / [JSON](../../fixtures/windows-collection/security.device_guard.json) | `device.security.windows.vbs_runtime` |
| `security.firewall` | 15063 | [devicestatus](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp) | [XML](../../fixtures/windows-collection/security.firewall.xml) / [JSON](../../fixtures/windows-collection/security.firewall.json) | `device.security.windows.firewall.status` |
| `security.hvci` | 22000 | [devicestatus](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp) | [XML](../../fixtures/windows-collection/security.hvci.xml) / [JSON](../../fixtures/windows-collection/security.hvci.json) | `device.security.windows.hvci_runtime` |
| `software.non_store` | 10586 | [enterprisemodernappmanagement](https://learn.microsoft.com/en-us/windows/client-management/mdm/enterprisemodernappmanagement-csp) | [XML](../../fixtures/windows-collection/software.non_store.xml) / [JSON](../../fixtures/windows-collection/software.non_store.json) | `device.software.windows.non_store.id` |
| `software.store` | 10586 | [enterprisemodernappmanagement](https://learn.microsoft.com/en-us/windows/client-management/mdm/enterprisemodernappmanagement-csp) | [XML](../../fixtures/windows-collection/software.store.xml) / [JSON](../../fixtures/windows-collection/software.store.json) | `device.software.windows.store.id` |
| `software.system` | 10586 | [enterprisemodernappmanagement](https://learn.microsoft.com/en-us/windows/client-management/mdm/enterprisemodernappmanagement-csp) | [XML](../../fixtures/windows-collection/software.system.xml) / [JSON](../../fixtures/windows-collection/software.system.json) | `device.software.windows.system.id` |
| `software.win32` | 10240 | [win32appinventory](https://learn.microsoft.com/en-us/windows/client-management/mdm/win32appinventory-csp) | [XML](../../fixtures/windows-collection/software.win32.xml) / [JSON](../../fixtures/windows-collection/software.win32.json) | `device.software.windows.win32.id` |
| `updates.failed` | 15063 | [update](https://learn.microsoft.com/en-us/windows/client-management/mdm/update-csp) | [XML](../../fixtures/windows-collection/updates.failed.xml) / [JSON](../../fixtures/windows-collection/updates.failed.json) | `device.updates.windows.failed.id` |
| `updates.installable` | 15063 | [update](https://learn.microsoft.com/en-us/windows/client-management/mdm/update-csp) | [XML](../../fixtures/windows-collection/updates.installable.xml) / [JSON](../../fixtures/windows-collection/updates.installable.json) | `device.updates.windows.installable.id` |
| `updates.installed` | 15063 | [update](https://learn.microsoft.com/en-us/windows/client-management/mdm/update-csp) | [XML](../../fixtures/windows-collection/updates.installed.xml) / [JSON](../../fixtures/windows-collection/updates.installed.json) | `device.updates.windows.installed.id` |
| `updates.pending_reboot` | 15063 | [update](https://learn.microsoft.com/en-us/windows/client-management/mdm/update-csp) | [XML](../../fixtures/windows-collection/updates.pending_reboot.xml) / [JSON](../../fixtures/windows-collection/updates.pending_reboot.json) | `device.updates.windows.pending_reboot.id` |
| `updates.scan` | 10240 | [update](https://learn.microsoft.com/en-us/windows/client-management/mdm/update-csp) | [XML](../../fixtures/windows-collection/updates.scan.xml) / [JSON](../../fixtures/windows-collection/updates.scan.json) | `device.updates.windows.last_scan` |

身份和硬件包也读取 [DevInfo](https://learn.microsoft.com/en-us/windows/client-management/mdm/devinfo-csp)。固定 DDF 与校验链位于 `crates/windows-mdm/schema`；DDF 未包含的 Win32AppInventory、Update 只读节点由 `schema/collection/source.json` 固定官方正文与 SHA-256，生成器验证后输出同一 schema 表。

动态采集执行“枚举 → 子项读取 → 对所有已枚举目录复核一次”。包应用按 origin、PackageFamilyName、PackageFullName 保留身份，Win32 按原生记录 URI 标识；网络与更新也保留原生 URI。只有两次目录集合一致且所有叶子成功，才产生完整清单（允许明确的空数组）。这不是终端原子快照：未改变目录身份的属性变化仍按各次读取观察记录。404、403、未知枚举、截断、缺失结果、超时、容量上限或目录变化均不会变成完整空列表；已确认其它字段仍可形成 Partial。Transcript 是协议关联和 MoreData 的唯一依据；集合进度与 run 同事务保存，重启不会把本轮响应接到其它请求。

每个包最多输出 1 MiB、300 秒；另受会话 128 条消息、32768 命令和协商消息大小限制。无法在预算内完成时保持失败/部分质量。软件、网络、注册字段含敏感资产信息，沿用 Inventory 授权和来源隔离。原始完整 URI 同时绑定设备注册与 run；当前 provider 外的注册对象不可通过标量绕过读取。

`device.software.windows.win32/store/non_store/system` 分开保存，不写入 Agent 的 `device.software.installations`。Win32 的 `Source` 为发现来源，不能据此推断 machine/user 安装范围，因此 `installation_scope=unknown`。包应用保留整数原值 `is_provisioned_native`；仅原值 0/1 派生可选布尔 `is_provisioned`。Windows 实机对 System 应用返回的 2 保留为原始观察值，布尔字段缺省，不推断为 true/false，也不丢弃整条应用。System 分类由 CSP 命名空间决定。新采集包业务版本为 2，已有字段目录通过正常字段版本写入扩展后，再发布并绑定新版资源。包应用还保留 `package_status` 以及 CSP `Users` 原文 `registered_users_native`，不把用户注册数据提升为独立 User 范围，也不推断安装者。完整空清单只替换该原生字段。

安全字段保留原生语义：Firewall 0 表示 enabled；Antivirus SignatureStatus 0 表示过期或缺失；DeviceGuard 的 0 表示运行，不能按普通布尔值转换。BitLocker 字段是 `DeviceEncryptionStatus` 合规错误位数组，0 为空错误集，不代表每个卷已经加密；未知位拒绝。TotalRAM 按文档的可用 MB 转为 `available_memory_bytes`，不冒充物理内存容量。Update 清单只读 UpdateID、RevisionNumber 及原生状态，没有 KB 补丁推断、扫描触发、批准或安装动作，不采集恢复密钥。

实例化示例：Resource `instantiate` 使用 `blueprint:"windows.software.win32", version:"2"`，激活后按既有 Policy 绑定。查询 run 使用 `GET /api/v1/devices/{device}/collections/{run}`；软件列表使用 `GET /api/v1/devices/{device}/inventory-lists/device.software.windows.win32?limit=100`，分页游标保留资产水位与来源。Group 可对上表对应字段建立规则；Missing、Unsupported、Partial 与来源冲突保持未知，不能当作“未安装”或“安全”。
