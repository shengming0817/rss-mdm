# Windows 注册与管理通道

本实现覆盖 #2350/#2351：Discovery、XCEP、WSTEP 签发与 I01 绑定、mTLS 管理准入，以及固定 APPSRV BASIC / CLIENT DIGEST 的首次 SyncML 认证和初始化。支持目标为 Windows 10 1809 及以上、Windows 11；T1/T2 不证明原生 Windows T3 已完成。CollectionRun 与资产采集由 [#2352/#2353](202609120000-2352-windows-inventory.md) 接入；广泛续期与 CA 轮转仍不在范围。

## 部署输入

[完整配置](../../fixtures/mdm-config.example.json) 中 `windows.enrollment`、`windows.management` 各有显式 listen、HTTPS origin、PEM 证书链和 DER PKCS#8 私钥文件。两个协议监听器由 Rust 终止 TLS，不能接到终止 mTLS 的反向代理后。四层转发可保留真实 TLS；不接受代理设备身份头。浏览器管理入口仍使用原有回环监听与受控 HTTPS 入口。

协议入口：

| 监听器 | POST 路径 | 身份 |
| --- | --- | --- |
| enrollment HTTPS | /EnrollmentServer/Discovery.svc | 无认证发现，持久审计 |
| enrollment HTTPS | /EnrollmentServer/Policy.svc | Enrollment UsernameToken、原管理员在线 Identity 与当前资源权限 |
| enrollment HTTPS | /EnrollmentServer/Enrollment.svc | 同上，加 CSR 持有证明 |
| management mTLS | /ManagementServer/MDM.svc | 真实叶证书链和每请求 PG 当前映射，再验证 SyncML 凭据 |

监听器的异常终止和连接 timeout/parse/io/panic 以闭合类别及可信监听器名称记录；不记录远端请求正文或错误原文。进程在启动运行时前安装固定 panic hook，仅输出 `mdm_panic` 事件，避免默认 hook 提前泄露 payload。两个 origin 必须不同，Host、SOAP To、SyncHdr 目标必须匹配配置；`provider_id` 使用不超过 64 字符的 ASCII 字母、数字、下划线或连字符。TLS 1.2/1.3、HTTP/1.1；禁用 TLS session resumption，管理请求仍逐次核验证书期限、clientAuth/digitalSignature/CA=false 及当前注册状态。叶 DER 的 SHA-256 唯一用于 I01 凭据查找，CSR subject、DeviceID、HTTP header 不能授予身份。

握手失败在持久审计之外保留 handshake_timeout、handshake_protocol、client_certificate 闭合诊断。CSR DER、算法、密钥长度或持有证明错误使用 CertificateRequest SOAP Fault；SOAP 结构错误仍使用 MessageFormat。

CA 输入为专用、自签 RSA CA 的 PEM 证书和受保护 DER PKCS#8 私钥。启动核验密钥匹配、有效期、CA 和 keyCertSign 用途；不加载通用 CA 服务。叶 RSA/SHA-256，公钥 2048–8192 位，默认 90 天且不越过 issuer 到期。证书库地址使用 Windows 要求的 SHA-1 thumbprint，这不改变管理认证的 SHA-256 指纹。

`protocol_key_file` 是独立随机 32 字节 AES-256-GCM 保护密钥，不能与 CA/TLS 私钥复用。私钥及秘密文件必须普通文件、非符号链接、仅 owner 可读写（例如 0600）；文件读取有尺寸上限。生产密钥由部署 owner 安全生成、备份并与 PG 一起保管；丢失保护密钥不能恢复原协议秘密。更换 CA、保护密钥、origin 或 provider 会改变配置身份，旧签发意图拒绝在不同配置下继续。

测试材料由 `hack/windows_fixtures.py` 自动生成，`make t2` 自动使用并销毁。测试私钥、口令和合成样本不能作为生产配置，也不入 Git。TLS 服务端证书必须受 Windows 信任且 SAN 匹配公开主机；私有根须事先配置到设备可信根，不能依赖尚未完成的 enrollment 为初次 HTTPS 建立信任。

## 注册与恢复

1. 管理员通过产品登录，获得当前 CSRF 值，按 [Enrollment API](202609090001-2347-enrollment-audit.md) 创建授权。调用端保留随机口令，设备 ID 必须与计划纳管设备的 WSTEP/DevInfo 标识一致。
2. Windows Discovery 可声明 RequestVersion 1.0–7.0，服务端返回 EnrollmentVersion 4.0；规范的可选 UX/域/设备上下文仅作无权声明。发现后，用 enrollmentId 和口令提交 GetPolicies 与 WSTEP Issue。组件凭据引用仅在最长 300 秒的服务端缓存中解析；它不能用于浏览器登录。每次协议授权都通过自有 PG 权威验证原管理员及当前设备范围。
3. 严格 DER CSR 解码和重新编码一致性检查、RSA/SHA-256 持有证明成功后，提交原 CSR、EnrollmentType、精确 TBS、issuer、配置身份、固定注册 ID 和加密协议秘密。CSR subject 和扩展不传递权限；签名算法参数接受标准 NULL 或省略。
4. ring 确定性 RSA PKCS#1 v1.5 签名后，AccessStore 原子完成证书、绑定、回执和成功审计，再向设备返回 provisioning。事务最后重新检查口令版本、授权期限、取消状态和预期世代。
5. 响应丢失重放原操作。数据库结果确认存在时取原证书；确认无结果时用同一意图重算同一证书。无法确认时返回未知，不换签发操作或 issuer。应用重启或管理员会话失效后由原管理员重新登录并 resume。

Full enrollment 将叶证书安装到 My/User，以完整 URI 转义 subject 和 `SSLCLIENTCERTSEARCHCRITERIA` 选择用户证书。Device enrollment 安装到 My/System，省略搜索 criteria，使用 enrollment 的私钥关联；Microsoft 的 Device 示例与 CSP 的 Stores 说明存在矛盾，此分支的原生选择行为必须在独立 T3 验收，当前只有生成结果与服务端组合证据。根证书放 Root/System。EntDMID 使用服务端已持久化的 registration UUID，协议账号也按注册隔离；EntDMID 的回传不代替 mTLS。

## 管理会话

固定 APPSRV BASIC 表示设备向服务端认证，CLIENT DIGEST 表示服务端向设备认证。DIGEST 使用 OMA MD5 与解码后的二进制 nonce；它和 CSR 的 RSA/SHA-256 是不同协议用途。独立协议秘密按 tenant + Enrollment 关联加密保存，响应和日志不输出管理员凭据。

首次请求包含 Alert 和完整 DevInfo；设备 Source/DevId 必须与已认证映射一致。会话固定 tenant、registration、generation、credential；SyncHdr 引用必须关联已保存的精确响应，不能根据客户端输入猜测期望。每条消息的摘要、关联、认证状态、nonce 和准确响应同事务提交，重复消息只返回原响应，同号不同内容、错 session/reference、跨设备请求拒绝。成功 Status 的 NextNonce 保存给下一会话；401/407 的 challenge 用于当前认证重试。nonce 解码后长度限制为 16–64 字节，初始值随机 32 字节。

每个会话最多 8 条消息、有效 15 分钟；每注册仅一个可推进会话，新会话取代旧未完成会话；旧会话只可重放原响应，不能回写 nonce。每监听器最多 128 个连接，TLS 握手 5 秒、HTTP 头 10 秒。请求体读取预算 8 秒，认证及各持久化阶段使用自身有界预算，另留 2 秒收尾审计。撤销成功审计与 I01 状态变更同事务；提交后新准入（包括已有 TLS keepalive 连接上的新请求）立即拒绝，已准入请求按上述预算完成；已接受输入封存后的历史报告恢复另遵循 CollectionRun 的持久授权边界。

连接和请求准入只使用真实 TCP peer IP，忽略转发头；四层代理或 NAT 后的设备共享该 peer 的限额。每 peer 最多 4 个连接、2 个在处理请求，连接突发 16、每秒恢复 1，请求突发 64、每秒恢复 4。每监听器连接突发 128、每秒恢复 32，请求突发 256、每秒恢复 64；三个 HTTP 入口共用 4 个业务处理槽，Discovery 也受限。peer 表上限 4096，空闲 5 分钟后可回收。进入业务处理前的连接拒绝直接关闭 TCP，请求拒绝返回 429；仅累计 `mdm_ingress_limited` 并在 2 的幂次数输出闭合计数，避免容量拒绝放大 PG 审计。通过准入后的请求和失败握手仍走持久审计。

协议响应仅保证在会话的 15 分钟窗口内精确重放。产品生命周期中的 `mdm-management-retention` 每秒尝试一批、最多锁定 128 个过期会话，使用 SKIP LOCKED，在同一事务先终结相关 CollectionRun，再删除响应和会话；每次预算 2 秒，SQL/锁预算 1 秒，瞬时失败留待下次有界尝试。过期后的 MsgID>1 拒绝；MsgID=1 必须按新会话重新认证，不能延续已清除的关联状态。RLS 只允许删除同租户过期临时行，清理不改变 Enrollment、证书、I01、操作回执或审计事实。部署 owner 监控清理失败事件及过期积压，停机期间积压在重启后按批次清理。

## 验证与来源

`make t2` 使用真实 PG、真实 RSA 签名和原生 Rust TLS 监听器，从 Discovery→XCEP→WSTEP 开始，覆盖 Host/To/认证拒绝、未绑定叶证书拒绝、响应丢失、保存失败、提交未知/取消、重启、口令轮换、期限/取消竞争、并发换代、审计失败、错误用途/期限、错租户/设备、精确重放、nonce 跨会话和撤销，并验证入口突发限流、过期清理的并发/回滚/重启/权限。Windows 入口要求两个指定测试均运行成功，零测试或部分运行直接失败。嵌入组件与可选 SSO 组合另由 `make t2-identity` 验证，完整本地门禁为提交后的 `make ci`。具体测试机不是本次实施前置。

独立 T3 需记录 Windows 10 1809+ 与 Windows 11 版本、Full/Device 实际注册方式、证书存储/私钥关联、Discovery/XCEP/WSTEP、第一次 SyncML 212 与后续 nonce、重启/响应丢失恢复及撤销。尤其检查 Device certificate selection 和 WSTEP DeviceID 与 SyncHdr/DevInfo 的实际一致性；未经真机验证不声明部署可用。

主要来源：[MS-MDE2 provisioning](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/35e1aca6-1b8a-48ba-bbc0-23af5d46907a)、[w7 APPLICATION CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/w7-application-csp)、[Windows server requirements](https://learn.microsoft.com/en-us/windows/client-management/server-requirements-windows-mdm)、[RFC 4055 §5](https://www.rfc-editor.org/rfc/rfc4055.html#section-5)。X.509 模型参考 RustCrypto x509-cert v0.2.5 `src/request.rs`；签名/验证参考 ring v0.17.14 `src/rsa/keypair.rs` 与 rustls v0.23.44 `src/webpki/client_verifier.rs`。协议顺序和 fixture 来源见 [codec 指南](202609080000-2349-windows-mdm-codec.md)。
