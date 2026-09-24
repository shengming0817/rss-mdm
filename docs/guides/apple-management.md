# Apple 手动注册、采集与 Profile 管理

本入口实现 Rust 服务端的设备通道，使用外部 step-ca v0.30.2 完成 SCEP 签发。覆盖手动 mobileconfig、Authenticate/TokenUpdate/CheckOut、Model/OSVersion 采集，以及单一设备防火墙 Profile 的安装、移除和存在性核实。受控 T2 不代替真实 Apple 组织、APNs 和 Mac 验收；T3 由 #2482 持有。不提供 ADE、DDM、用户管理或系统防火墙效果证明。

## 注册与凭据

管理员在线登录并拥有目标设备的 `enrollment` 权限后，调用 `POST /api/v3/enrollments`，提交 `deviceId`、`source:"mdm.apple"`、256 位随机 `password`，以及非零 UUID `Idempotency-Key`。返回 HTTP 200 的 pending 授权。生命周期整组已切换 v3，旧版本不挂载；Windows 使用 `mdm.windows`，Agent 使用 `agent.builtin`，不接受请求 `channel`。

设备通过 HTTPS `POST /api/v3/enrollments/{id}/profile` 提交 `{"password":"…"}` 下载附带 CMS 签名的 mobileconfig；响应不缓存。口令和配置只交付给授权设备。Profile 配置 RSA 2048 SCEP 身份、设备范围、AccessRights 19、生产 APNs topic、CheckOutWhenRemoved，以及 `per-user-connections` capability；`SignMessage=false`，管理传输必须使用原生 mTLS。UserAuthenticate 返回 410，不建立用户身份。

SCEP challenge 在返回 allow 前提交唯一消费事实，绑定 enrollment、签发 attempt、事务 ID、CSR 摘要、公钥和配置身份。相同请求重试也被拒绝。通知丢失时，首次携带匹配有效证书的 Authenticate 可完成绑定；签发响应丢失不能重新签发，须由原管理员 resume，换口令后重新下载 Profile。新 attempt 使用新密钥；活跃已消费公钥不能跨 attempt 复用。

CN 为 enrollment UUID 的 32 位小写 hex 与 attempt UUID 的 32 位小写 hex 直接拼接，长度 64。证书只接受专用 issuer、完整身份绑定、clientAuth EKU、digitalSignature、非 CA、无 SAN 和不超过 90 日的有效期。设备先进入 pending_token；TokenUpdate 验证 topic、UDID 并保存 token/PushMagic 后才允许管理投递。CheckOut、管理员撤销和换代均停用旧设备身份；旧证书、旧 source/epoch 或旧代际不能承接新任务。

## 采集

`POST /api/v1/devices/{id}/collection-runs` 请求为 `{"source":"mdm.apple","requestId":"非零 UUID"}`，要求设备级 `inventory_collect`。202 回执包含 `runId` 和 `result:"pending"`；相同 requestId 精确重放。同一事务冻结当前注册、generation、epoch、coverage、批准、十分钟期限和 DeviceInformation 请求。

设备 `/mdm` Idle 获取固定 Model/OSVersion 查询。只有准确关联的 CommandUUID 和当前身份才能封存结果。CollectionRun 不创建 device-command，也不产生 Applied。查询 `GET /api/v1/devices/{id}/collection-runs/{run}?source=mdm.apple` 需要 `inventory_read`，呈现每字段质量、服务端接收时间和真实 Observation 投递状态，Apple 字段没有伪造的 SyncML 数字状态。

完整 Snapshot 经既有 Observation/Inventory 投影。Partial/Failed 保留最后完整资产，最新质量由 CollectionRun 单独呈现；不拼接旧值伪造新 Snapshot，不引入字段 TTL。纯超时且没有字段结果只记录失败 run，不制造 Observation 报告。

## Profile 操作

整组 Commands 使用 `/api/v2`，包括计划执行。`POST /api/v2/devices/{id}/operations` 的请求为：

```json
{"operationId":"97c3820e-4698-47dc-bb09-b33bd53da2f0","task":{"kind":"profile_install","enabled":true},"deadline":1800000000}
```

示例 deadline 必须替换为未来 Unix 秒。要求设备级 `firewall_write`；同一 Identifier 的操作串行。Identifier 稳定绑定 tenant/device，安装 operationId 是 PayloadUUID。移除 task 为 `{"kind":"profile_remove","profile":"当前拥有的安装 UUID"}`，不能移除其他 UUID。任务类型自身决定协议，不接受 executor 字段。查询、取消和重新批准沿用 [Commands](device-operations.md) 的 operation_read/operation_cancel、requestId 和 expectedRevision 契约。

| 证据 | commandStatus 含义 |
| --- | --- |
| 事务内受理和 outbox 保存 | queued |
| 内部 dispatch 成功发布 | published |
| APNs 200 | 仅接受唤醒，不推进 command |
| 精确关联安装/移除 ACK | received |
| NotNow | 保留待执行，延迟重投同一请求身份 |
| Error / CommandFormatError | rejected |
| 完整、关联 ProfileList 与预期 identifier/UUID/存在性匹配 | applied |

ProfileList 查询不设置 ManagedOnly，使用完整列表，避免依赖尚未确定的 OS 版本。无列表或不完整字段不证明缺失；同 Identifier 的不同 UUID 是 mismatch。查询 observation 带 `protocol:"mdm.apple"` 和 `observationScope:"profile_presence"`；`effect:"unknown"` 明确不证明 OS 防火墙已生效。错误 UUID、越权或旧代际 ACK 不产生成功；存在性不匹配保留 received 和 mismatch/unknown，直到取消或超时。

APNs 使用证书认证 HTTPS/HTTP2，token revision 和持久唤醒 lease 隔离过期回执。410 使对应当前 token 回到 pending_token；旧 revision 的 410 不撤销新 token。429 和网络失败按 30、60、120 秒递增退避，5xx 至少等待 900 秒，均封顶 960 秒，不改变命令结果。按闭合 APNs reason 判定 token 失效、配置拒绝或暂时故障；未知/畸形响应可重试，配置拒绝暂停当前 token revision/APNs 证书组合；TokenUpdate 或更换有效 APNs 证书并重启后可恢复。失效授权的采集会延后检查，不能持续占据有界队列前页。

APNs 唤醒在持久 lease 的授权事务完成时取得发送资格。已领取或已被 APNs 接受的提示可能在撤销后才到达；提示本身不包含业务命令，后续设备请求仍必须通过当前注册、代际、来源及操作授权校验。

## 产品配置

完整配置仍由 [mdm-config.example.json](../../fixtures/mdm-config.example.json) 展示数据库与 Identity 装配。必填 `native_protocols` 是闭合对象：`{}` 为 Agent-only；只有 windows 为 Windows-only；只有 apple 为 Apple-only；两者同时存在则启动各自监听。成员缺席表示关闭，显式 null 和旧顶层 windows 均拒绝。Apple-only 不需要 Windows issuer 或保护密钥。

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

`apple_push_result` 包含 registration、token revision、HTTP status、outcome 及闭合 failure 类别。`transport` 表示连接/TLS/传输失败，`certificate_expired` 表示本地 APNs 材料到期。429/网络失败使用封顶 960 秒的退避，5xx 至少等待 900 秒；已知 token 失效 reason 清除当前 token/PushMagic 并等待 TokenUpdate；配置拒绝暂停相同 token revision 与 APNs 证书组合。修复证书配置后重启，或收到新 TokenUpdate 后恢复。以上状态都不推进命令结果；不得据 APNs 成功判断 Profile 已安装。
## 续期与后台故障观测

设备身份采用服务端受控的注册 profile 更新，step-ca 的通用 renewal 仍保持禁用；每次签发必须消费产品准备的一次性 challenge。配置身份变化仍要求重新注册，不会借续期接受漂移。监控 `apple_identity_health` 的 `renewal_due`/`expired` 和 `apple_identity_renewal`；离线跨过证书到期的设备使用人工重新注册恢复。

APNs 响应体最多读取 4096 字节，仅记录闭合原因类别和可选时间戳，不输出 provider 原始文本。失效 token 退回 pending_token；证书、topic、请求或 payload 错误暂停该配置；限流/网络/服务端错误退避，5xx 至少等待 15 分钟。未知或畸形响应按可重试协议错误处理。

后台 `apple_push_health` 记录连续内部失败数和配置故障。连续三次内部失败使 readiness 返回 503；数据库恢复后自动解除。配置拒绝保持不健康直到有效发送恢复或更换配置并重启。临时 APNs 网络错误使用设备级持久退避，不伪造命令进度。
