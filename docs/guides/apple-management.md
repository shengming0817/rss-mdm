# Apple 原生注册、命令与 Profile 管理

Rust 服务端支持设备和用户通道，使用外部 step-ca v0.30.2 完成 SCEP 签发。原生命令、查询、回执和多 payload Profile 复用现有 Execution、注册及采集 owner。DDM 的声明发布与状态证据由 Apple 原生 owner 持有；组织/ADE 入网独立实施，这里的 Bootstrap escrow 不代表已实现 ADE 入网。受控 T2 不代替真实 Apple 组织、APNs 和 Mac 验收，T3 证据另行登记。

## 注册与凭据

管理员在线登录并拥有目标设备的 `enrollment` 权限后，调用 `POST /api/v3/enrollments`，提交 `deviceId`、`source:"mdm.apple"`、256 位随机 `password`，以及非零 UUID `Idempotency-Key`。返回 HTTP 200 的 pending 授权。生命周期整组已切换 v3，旧版本不挂载；Windows 使用 `mdm.windows`，Agent 使用 `agent.builtin`，不接受请求 `channel`。

设备通过 HTTPS `POST /api/v3/enrollments/{id}/profile` 提交 `{"password":"…"}` 下载附带 CMS 签名的 mobileconfig；响应不缓存。口令和配置只交付给授权设备。Profile 配置 RSA 2048 SCEP 身份、设备范围、AccessRights 8191、生产 APNs topic、CheckOutWhenRemoved，以及 `per-user-connections`、`bootstraptoken` capability；`SignMessage=false`，管理传输必须使用原生 mTLS。UserAuthenticate 在已绑定 mTLS 身份下返回空 DigestChallenge；不接收目录密码或建立业务账户身份。服务端保存设备实际安装 profile 的权限；后来启用 Agent 安装配置不会增加已有设备权限，也不会使其原生身份失效。缺少查询或安装权限时，策略返回 missing_native_rights，需通过正常注册流程取得用户/系统授权。

SCEP challenge 在返回 allow 前提交唯一消费事实，绑定 enrollment、签发 attempt、事务 ID、CSR 摘要、公钥和配置身份。相同请求重试也被拒绝。通知丢失时，首次携带匹配有效证书的 Authenticate 可完成绑定；签发响应丢失不能重新签发，须由原管理员 resume，换口令后重新下载 Profile。新 attempt 使用新密钥；活跃已消费公钥不能跨 attempt 复用。

CN 为 enrollment UUID 的 32 位小写 hex 与 attempt UUID 的 32 位小写 hex 直接拼接，长度 64。证书只接受专用 issuer、完整身份绑定、clientAuth EKU、digitalSignature、非 CA、无 SAN 和不超过 90 日的有效期。设备先进入 pending_token；TokenUpdate 验证 topic、UDID 并保存 token/PushMagic 后才允许管理投递。CheckOut、管理员撤销和换代均停用旧设备身份；旧证书、旧 source/epoch 或旧代际不能承接新任务。

## 用户通道与 Bootstrap Token

原生用户 GUID 绑定当前租户、设备注册及世代，共用设备身份凭据。UserAuthenticate 不授予资源权限；用户 TokenUpdate 分别保存加密 token/PushMagic、revision、租约与失效状态。operation 的 `target` 为 `{"kind":"user","userId":"规范小写非零 UUID"}`。设备前提只从设备通道查询，实际用户命令、回执和 ProfileList 只在该用户通道关联。每个通道的 410 只停用该通道；设备 token 失效后，已取得设备前提的用户命令仍可收发。设备 CheckOut/撤销/换代统一退役所有通道、Profile history 和 Bootstrap 材料。

GetBootstrapToken/SetBootstrapToken 由已绑定的设备证书认证，只有同世代已接受的原生证据明确确认监督、ADE 及 device enrollment 后可使用；缺失证据返回 Unsupported。没有 token 时 GET 成功但省略 BootstrapToken，SET 缺失或零长度 token 清除 escrow。材料按租户、注册世代、用途及 revision 加密，响应禁止缓存。此接口不把 token、UserID 或 AuthToken 变成浏览器业务授权。

## 采集

`POST /api/v1/devices/{id}/collection-runs` 请求为 `{"source":"mdm.apple","requestId":"非零 UUID"}`，要求设备级 `inventory_collect`。202 回执包含 `runId` 和 `result:"pending"`；相同 requestId 精确重放。同一事务冻结当前注册、generation、epoch、coverage、批准、十分钟期限和 DeviceInformation 请求。

设备 `/mdm` Idle 获取固定 Model/OSVersion 查询。只有准确关联的 CommandUUID 和当前身份才能封存结果。CollectionRun 不创建 device-command，也不产生 Applied。查询 `GET /api/v1/devices/{id}/collection-runs/{run}?source=mdm.apple` 需要 `inventory_read`，呈现每字段质量、服务端接收时间和真实 Observation 投递状态，Apple 字段没有伪造的 SyncML 数字状态。

完整 Snapshot 经既有 Observation/Inventory 投影。Partial/Failed 保留最后完整资产，最新质量由 CollectionRun 单独呈现；不拼接旧值伪造新 Snapshot，不引入字段 TTL。纯超时且没有字段结果只记录失败 run，不制造 Observation 报告。

## 原生操作与 Profile

设备 operation 使用 `POST /api/v3/devices/{id}/operations`，与 Policy/Resource 共用类型化原生输入。请求固定 `operationId`、`inputVersion`、`target`、`task` 和未来 Unix 秒 `deadline`。例如：

```json
{"operationId":"97c3820e-4698-47dc-bb09-b33bd53da2f0","inputVersion":"v1","target":{"kind":"device"},"task":{"platform":"macos","request":{"kind":"command","command":{"requestType":"InstalledApplicationList","fields":{}}}},"deadline":1800000000}
```

原生字段显式保留 plist 类型：`string`、`boolean`、十进制字符串 `integer`、`unsigned`、`real`、`date`、Base64 `data`、`array` 和 `dictionary`。`RunScript` 返回 Unsupported；原生操作不会转成 Agent 脚本。平台合同来自固定 Apple release 和 macOS 15 起的必要历史定义，实际 OS、硬件、监督、注册方式、通道及安装的 AccessRights 由认证设备证据判定。设备先回答原生前提查询，服务端不会采用浏览器提交的可信平台事实。

查询、应用/PKG、安全、账户、控制、设置和 OS 更新各自保留原生结果。查询完成可结束共同命令，但报告的 Unknown、安装中或拒绝仍是设备数据；ACK 仅证明接收。待重启、用户延后、错误及 Unknown 单独呈现，不能据此宣布安装、更新或合规成功。详细原生结果读取同时要求 operation_read 和原操作权限；目录只显示摘要。PKG 原生命令不建立固定 Agent 准入，后者继续由既有安装策略与软件 owner 负责。

Profile 使用 `request.kind:"install_profile"` 和 `profile`，其中根及每个 payload 分别指定原生 identifier/UUID、metadata、schema 路径与 fields；移除使用 `request.kind:"remove_profile"`、identifier 和拥有的 UUID。完整输入见 [Profile 类型](../../crates/apple-mdm/src/native/profiles.rs)。`PayloadVersion=1` 属于 Apple 格式，`inputVersion` 属于内容版本。编译器决定 System/User scope，拒绝重复身份、单实例冲突和无效同 Profile 证书引用；客户端不能覆盖这些编译器字段。

同一注册世代及通道内的 identifier 串行。已发出的未知副作用继续占有 guards；取消、超时或错误回执本身不释放它们。Profile owner 加密保存完整派发 manifest；替换或移除必须经当前、关联、接受的 ProfileList 证据确认。安装观测同时比较根和全部 payload 的 type/identifier/UUID/version；缺失、加密或不完整清单不证明替换完成。同一操作的接受 Error 后，完整清单证明安装目标确实缺席，或精确证明待移除的旧安装及全部 payload 仍在，才终结为 rejected 并退休该次失败预留；旧安装所有权继续保留。旧世代、旧尝试、晚到或越权回执不能覆盖新所有权。

| 证据 | 含义 |
| --- | --- |
| 事务受理和 outbox 保存 | queued |
| 内部发布完成 | published |
| APNs 200 | 接受唤醒，不推进命令 |
| 精确关联 ACK | received |
| NotNow | 延迟重投同一 UUID 和不可变请求 |
| Profile Error / CommandFormatError | 保留未知副作用，独立查询存在性 |
| 完整且接受的 ProfileList 匹配 | applied，仅证明原生对象存在性 |
| Error 后完整反向证据 | rejected，仅释放本次失败预留，保留旧安装 guards |

不重投已发送且结果未知的变更；只读恢复复用现有 attempt 流并有次数与期限上限。只读观测查询的错误不证明原变更被拒绝，仍保留其不确定性。Profile 存在、OS 设置效果及合规分别记录，`effect:"unknown"` 不证明防火墙或其他设置已生效。查询、取消和重新批准沿用 [Execution](device-operations.md) 的 requestId 与 expectedRevision 契约。

APNs 使用证书认证 HTTPS/HTTP2，token revision 和持久唤醒 lease 隔离过期回执。410 使对应当前 token 回到 pending_token；旧 revision 的 410 不撤销新 token。429 和网络失败按 30、60、120 秒递增退避，5xx 至少等待 900 秒，均封顶 960 秒，不改变命令结果。按闭合 APNs reason 判定 token 失效、配置拒绝或暂时故障；未知/畸形响应可重试，配置拒绝暂停当前 token revision/APNs 证书组合；TokenUpdate 或更换有效 APNs 证书并重启后可恢复。失效授权的采集会延后检查，不能持续占据有界队列前页。

APNs 唤醒在持久 lease 的授权事务完成时取得发送资格。已领取或已被 APNs 接受的提示可能在撤销后才到达；提示本身不包含业务命令，后续设备请求仍必须通过当前注册、代际、来源及操作授权校验。

## DDM 声明与状态

operation 的 Apple 请求为 `{"kind":"declarations","declarations":[…],"assets":[…]}`；两个数组都必填，空 declarations 撤回当前调用方的集合。声明包含 identifier、declarationType 和类型化 payload，四类原生声明使用同一冻结版本/条件编译。StatusItems 订阅是 `com.apple.configuration.management.status-subscriptions` 配置声明中的 Name 数组，Apple 自动报告 management.declarations，无需显式订阅。其它状态按当前作用域合并有效订阅；未知或当前平台不支持的名称被拒绝。

原生客户端经现有 mTLS `PUT /checkin` 发送 DeclarativeManagement plist，Endpoint 支持 tokens、declaration-items、declaration/{activation|configuration|asset|management}/{identifier} 和 status。读取返回原生 JSON，缺少对象返回 404；status 的 Data 为原生 JSON 报告，成功返回 200 空 body。启用/唤醒同步使用现有 MDM attempt 的 DeclarativeManagement 命令，不建立第二套队列。

下载资产的 binding 指定 identifier、resource、version、variant、versionDigest（32 字节数组）、contentType 和 profileSchemas。Resource 必须是已上传受保护内容的不可变 configuration 版本；版本摘要、内容长度/摘要、架构和当前 ResourceRead 均复核。服务器提供 HTTPS DataURL/ProfileURL 和原生 MDM Authentication，拒绝任意外部下载 URL。Legacy Profile 使用未签名 plist 内容，并按载荷顺序列出准确 Profile schema；签名 CMS 不作为这一路径的原始 Profile 输入。

产品支持受保护的 `com.apple.configuration.legacy`；`com.apple.configuration.legacy.interactive` 在准入时拒绝。

operation observation 分别返回 expected、synchronization、nativeStatus、effect 和 compliance。原生状态区分 valid/invalid/unknown、active 与 reasons；共同 applied 仅表示精确版本的声明核验完成。空集合撤回的 ACK 和无版本缺席报告不会证明终端移除。乱序的同版本冲突、未关联版本的增量状态保持 Unknown；receivedAt 只表示服务器收到证据的时间。详细值仍需要 operation_read 及原操作全部权限；Profile 原始清单还需要 inventory_collect，缺少权限时仍可读取核验摘要。每作用域最多 16 个有效 publication，累计状态预算为每个 512 KiB，预算耗尽后明确 Unknown；这些报告不自动成为 Inventory Snapshot 或合规成功。

`make t2 MODULE=apple.ddm` 验证四类声明、资产、重启、Legacy 接管和 Policy 所有权；`MODULE=apple.status` 验证冲突、作用域和撤权。真实 Mac 的同步、状态与 Profile 交接属于独立 T3，缺口登记为 [#2647](https://dev.azure.com/shengming0923/rss/_workitems/edit/2647)。

## 产品配置

完整配置仍由 [mdm-config.example.json](../../fixtures/mdm-config.example.json) 展示数据库与 Identity 装配。必填 `native_protocols` 是闭合对象：`{}` 为 Agent-only；只有 windows 为 Windows-only；只有 apple 为 Apple-only；两者同时存在则启动各自监听。成员缺席表示关闭，显式 null 和旧顶层 windows 均拒绝。Apple-only 不需要 Windows issuer 或 Windows 专用协议保护密钥，但仍必须提供顶层 `native_protection_key_file`（恰好 32 原始字节）。全局密钥保护 Apple 原生输入、回执与内容，多实例必须一致；生成、权限和配套恢复见 [安装](../deployment/installation.md) 与 [运维](../deployment/operations.md)。

将 native_protocols 替换为以下 Apple-only 配置，路径由部署环境提供：

```json
{"apple":{
  "management":{"listen":"0.0.0.0:8445","origin":"https://apple.example.test:8445","certificate_file":"/run/mdm/apple-tls.pem","private_key_file":"/run/mdm/apple-tls.pk8"},
  "scep_url":"https://ca.example.test/scep/rss","scep_provisioner":"rss",
  "issuer_certificate_file":"/run/mdm/apple-issuer.pem",
  "profile_certificate_file":"/run/mdm/profile-signer-chain.pem","profile_private_key_file":"/run/mdm/profile-signer.pk8",
  "apns_certificate_file":"/run/mdm/apns.pem","apns_private_key_file":"/run/mdm/apns.key",
  "apns_topic":"com.apple.mgmt.External.REPLACE",
  "challenge_webhook":{"id":"REPLACE-challenge-id","secret_file":"/run/mdm/challenge-secret"},
  "notify_webhook":{"id":"REPLACE-notify-id","secret_file":"/run/mdm/notify-secret"}
}}
```

TLS 与 Profile RSA 私钥为无加密 PKCS8 DER；APNs 私钥为 PEM。秘密文件权限必须限制为 owner，webhook secret 文件保存 CA 发放的 base64 字符串，解码至少 32 字节。两个 webhook ID/secret 分开配置。APNs certificate UID 必须等于 topic，且证书在有效期内。产品管理监听直接完成 mTLS，不接受代理头作为设备身份。

管理 origin、SCEP URL/provisioner、issuer 指纹、APNs topic 与两个 webhook ID 组成注册配置身份。改变这些身份会拒绝旧注册继续准入，须安排重新注册；仅更换同 ID 的 HMAC secret 不改变配置身份，但两端必须同步更新。不得把配置漂移当作证书恢复。
## 外部 CA 配置

部署专用 Apple issuer 与独立 CA 数据库，保护 CA signer/decrypter、管理员和 webhook 秘密。使用固定版本 step CLI 的管理员 API 创建 SCEP provisioner 与 webhook；静态 JSON 的 `secret` 不会建立有效 webhook 密钥。固定二进制摘要由 [tools lock](../../fixtures/apple-tools.lock.json) 持有，测试安装代码可参考 [apple_ca.py](../../hack/apple_ca.py)。

SCEP provisioner 名为 rss，最小 RSA 公钥 2048、禁用 renewal，默认签发 24h，最大时长应小于 90 日以包含 backdate。配置 SCEP RSA decrypter 证书与密钥。签名模板只使用经 HMAC 回调授权返回的主题：

```json
{"subject":{"commonName":{{ toJson .Webhooks.rss.subject }}},"keyUsage":["digitalSignature"],"extKeyUsage":["clientAuth"],"basicConstraints":{"isCA":false}}
```

通过 `step ca provisioner webhook add rss rss --kind SCEPCHALLENGE --url https://mdm.example.test/native/apple/scep/challenge` 配置 challenge；通过 `step ca provisioner webhook add rss rss_notify --kind NOTIFYING --url https://mdm.example.test/native/apple/scep/notify` 配置通知。命令需附该部署的 ca-url/root/admin 身份参数；分别将输出 ID 和 secret 写入受保护配置。不能把通知类型写成不存在的 SCEPNOTIFY。

配置后重启 CA，确认 `/scep/rss?operation=GetCACaps` 可访问：该版本只在启动时安装 SCEP HTTP authority。Webhook HTTPS 证书须被 CA 的系统信任根或配置 root 信任；`federatedRoots` 不参与该版本 webhook TLS 客户端验证。生产应使用受信任服务证书，不能禁用 TLS 校验。产品要求 Host 与 product_origin 精确一致，反向代理保持 Host 并转发原始请求体和 X-Smallstep-Webhook-ID/X-Smallstep-Signature。

challenge 是一次性事务，先消费提交再 allow；CA 的重复传输不能再次授权。签发完成通知不是唯一绑定通道，真实 mTLS 叶证书可恢复丢失通知；签发响应本身丢失须新口令、新 attempt、新密钥，不能静默重签。
## 健康、告警与排障

启用 Apple 后，`/readyz` 同时检查 SCEP issuer、Profile signer 和 APNs 证书有效期；任一过期即返回 503。后台输出 `apple_certificate_health`：用途为 `scep_issuer`、`profile_signer`、`apns`，剩余 30 日进入 `renew_soon`、7 日进入 `critical`、到期为 `expired`。每次进程运行仅在等级变化时输出；应由部署日志告警系统接收。替换材料后重启以装载新证书；issuer 变化仍须按注册配置身份规则重新注册，APNs/签名证书同一用途轮换不改变注册身份。

启动失败按闭合类别定位：`AppleListeners`、`AppleScep`、`AppleProfileSigner`、`AppleApns`、`AppleChallengeWebhook`、`AppleNotifyWebhook`；不会输出路径、密钥、口令或 provider 原文。

`apple_push_result` 包含 wake ID、device/user 通道类别、registration、token revision、HTTP status、outcome 及闭合 failure 类别。坏加密推送材料只隔离所属通道为 pending_token，等待真实 TokenUpdate 恢复；`apple_push_material_rejected` 输出闭合完整性类别及带密钥的 scope 摘要，健康候选继续处理。全局数据库失败继续影响 readiness，错误保护密钥由启动绑定拒绝。`transport` 表示连接/TLS/传输失败，`certificate_expired` 表示本地 APNs 材料到期。429/网络失败使用封顶 960 秒的退避，5xx 至少等待 900 秒；已知 token 失效 reason 清除当前 token/PushMagic 并等待 TokenUpdate；配置拒绝暂停相同 token revision 与 APNs 证书组合。修复证书配置后重启，或收到新 TokenUpdate 后恢复。以上状态都不推进命令结果；不得据 APNs 成功判断 Profile 已安装。
## 续期与后台故障观测

设备身份采用服务端受控的注册 profile 更新，step-ca 的通用 renewal 仍保持禁用；每次签发必须消费产品准备的一次性 challenge。配置身份变化仍要求重新注册，不会借续期接受漂移。监控 `apple_identity_health` 的 `renewal_due`/`expired` 和 `apple_identity_renewal`；离线跨过证书到期的设备使用人工重新注册恢复。

APNs 响应体最多读取 4096 字节，仅记录闭合原因类别和可选时间戳，不输出 provider 原始文本。失效 token 退回 pending_token；证书、topic、请求或 payload 错误暂停该配置；限流/网络/服务端错误退避，5xx 至少等待 15 分钟。未知或畸形响应按可重试协议错误处理。

后台 `apple_push_health` 记录连续内部失败数和配置故障。连续三次内部失败使 readiness 返回 503；数据库恢复后自动解除。配置拒绝保持不健康直到有效发送恢复或更换配置并重启。临时 APNs 网络错误使用设备级持久退避，不伪造命令进度。

Mac 的 Legacy 接管以关联的 `ProfileList(ManagedOnly=true)` 证明 MDM 所有权，不依赖 iOS 的 IsManaged 字段。资源读取权限按租户作用域冻结，与设备配置权限分别验证。
