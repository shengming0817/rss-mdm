# Certificate archive / 项目证书目录

本模块归 rss-mdm，提供租户隔离的加密存档、证书/申请材料生成、完整历史和到期提醒。
App 持有数据库连接与生命周期，management-http 适配管理接口，rss-web 的“安全管理 → 证书存档”消费真实 API。
其他服务仍按各自配置读取证书文件；下载、推荐版本和人工使用位置不证明已经部署。

## 开始使用

1. 用已有租户授权管理给管理员授予 `certificate_archive_read`、`certificate_archive_write`、`certificate_archive_unlock`、`certificate_archive_export` 中所需权限。权限采用 Tenant scope；主密码不替代网页登录和权限。
2. 在存档页面设置租户主密码，至少 12 个字符；将密码保存在独立的企业密码管理器中。不要放在数据库备份旁或服务配置中。
3. 输入密码解锁当前登录会话 15 分钟，再导入材料或生成证书/CSR。新类别、标签、使用位置和负责人可直接配置。
4. 每次导入、生成或修改说明都追加版本；历史文件与当时说明不覆盖。退役和推荐版本只影响管理标记。任一版本均可授权导出，导出可能包含私钥。
5. 将导出的材料人工配置到实际消费服务，按对应指南重启/替换并验证，再记录使用位置。这里不自动部署、替换或探测已加载证书。

首次安装包含 `mdm_certificate_archive` schema。遵循产品现有空库安装/准确安装记录重放规则，不支持旧库升级；见[安装](../../docs/deployment/installation.md)和[运维](../../docs/deployment/operations.md)。

## 密码、重启、换密码与备份

每租户随机生成独立的 32 字节数据密钥 K。密码和随机 salt 经 Argon2id 派生保护密钥，用于加密 K；材料使用 K 经既有 AES-256-GCM 保护。密文绑定租户、条目、版本和存档用途。数据库只保存密文、salt、固定 KDF 标识及密码保护世代，不保存主密码或明文 K。

解锁按租户、实例、管理员和登录会话绑定，单次 15 分钟，不因读取延长。缓存只在当前服务实例内，定时清理；服务重启或请求落到另一实例时需要再次解锁。权限和登录会话每次请求检查，敏感操作检查当前密码保护世代。没有配置密码文件、跨实例共享明文缓存或启动时自动解锁。

换密码必须验证旧密码，再用新密码和新 salt 保护**同一个 K**，因此全部历史材料继续可读。换密码使已有解锁失效。响应丢失时查询原操作 ID；精确重试核对原回执，不创建第二次修改。数据库里的当前保护记录原子替换，记录的历史不属于证书历史。

备份使用正常 PostgreSQL 完整备份，包含 schema、角色/权限以及全部 `mdm_certificate_archive` 表；恢复到匹配的产品安装后，用备份时有效的密码解锁。保存密文材料但遗漏受保护的 K 或 salt，无法恢复。较旧备份仍需要当时的密码，当前新密码不会使旧备份自动变化。

将主密码和备份分开保存。遗失主密码且没有可用解锁/对应备份密码时，不能恢复敏感材料；没有明文回退或管理员重置绕过。读取元数据和到期信息不需要解锁。

## 文件格式与生成能力

支持 X.509 PEM/DER、PEM 链、PKCS#10 PEM/DER CSR、PFX/P12 和 PEM/DER 私钥。单次最多 16 个原始文件，合计 1 MiB。声明支持的格式解析失败时拒绝；未知格式须明确选“原样归档”，标为未解析。原文件密码只参与本次解析，不保存。

原始 PFX 或加密私钥文件保持原样，导出原件仍使用原文件密码。解析成功时另存加密保护的 PKCS#8 私钥副本；PFX 另存主证书 PEM，其他链成员保留在原件与信息列表中。所有这些副本随同一版本导出，默认不在页面显示私钥。不可导出的终端、HSM、EV 签名私钥不要求上传；保存公开证书、持有方和恢复说明即可。

| 生成用途 | 产出与约束 |
|---|---|
| 本地 CA | 自签 CA、对应密钥和 CSR；CA=true、keyCertSign/crlSign；默认十年 |
| 私有 HTTPS | 使用同租户存档 CA 的匹配私钥签发；必须有 DNS/IP SAN，serverAuth，默认一年；不超过 CA 到期时间 |
| 外部签发 CSR | 本地密钥和已验签的 PKCS#10 CSR；按实际外部平台提交，导入结果时关联 CSR 版本以检查公钥；精确条目/版本引用保存在签发结果的历史中，修改说明后仍保留 |
| APNs 前置 CSR | RSA 2048、SHA-256 CSR 和对应私钥；没有 MDM Vendor 签名时不能直接当成 Apple 可接受的最终申请材料 |
| SCEP 模板 | HTTPS 申请地址、主体、算法、设备持钥及信任配置说明；挑战由注册服务提供，不包含真实授权或设备私钥 |

本地算法支持 RSA 2048/3072、P-256；默认 RSA 2048。软件签名与 Apple 等外部身份的有效期和密钥形式由平台/CA 决定，不套用本地十年 CA 默认值。CSR、私钥和 SCEP 模板没有证书到期时间。

过期、临近到期、未生效以证书时间计算；默认提醒提前 30 天，可修改。链成员分别展示，提醒统计未退役条目的最新材料。推荐版本是人工标记，不能据此判断实际正在使用的证书。时间状态不等于链受信、用途可用或未撤销。

## 全项目证书清单

“现有”指当前代码的消费方式，“计划”指尚由设备认证相关任务实现的能力。本存档模块不会将计划能力变成现有设备认证。

| 证书/信任材料 | 用途及实际持有方 | 当前消费/配置入口 | 生成、外部依赖和更新方式 |
|---|---|---|---|
| 企业 HTTPS 服务器证书及链 | 网关和 Windows 注册/管理、Apple 管理监听的服务器身份；私钥由相应服务/网关持有 | 网关 nginx TLS；原生监听 `certificate_file` / `private_key_file`，见[配置样本](../../fixtures/mdm-config.example.json)与[原生配置类型](../app/src/assembly/apple/config.rs) | 公共 CA 申请，或私有 CA 签发；SAN 覆盖所有实际域名；人工替换文件并验证 |
| 企业 HTTPS 信任 CA | Agent、桌面及客户端信任服务器；只需要公开根/链 | rss-mdm-agent `Deployment.ca_file` → `Config.ca_pem`；平台信任配置 | 导入组织/公共 CA 信任材料；并不是客户端身份证书 |
| Windows MDM CA | 为 Windows 原生注册签发设备身份；CA 私钥归服务端 | `native_protocols.windows.ca_certificate_file` / `ca_private_key_file`；[Windows 指南](../../docs/guides/windows-management.md) | 本地 CA 可生成；现有签发器要求 RSA、自签 CA，按当前 profile 验证；替换涉及设备信任，须单独安排 |
| Windows 逐设备 MDM 身份证书 | Windows 原生管理的设备身份；私钥由设备持有 | 注册服务、Windows WSTEP/管理协议；[Windows certificate owner](../certificate/src/windows.rs) | 注册时签发；每台设备独立；当前设备 profile 有自己的短期有效期，不能改用存档 CA 的十年默认 |
| Apple SCEP CA / 签发链 | macOS 原生身份申请的签发/信任链；签发私钥归服务端，信任材料归设备 | Apple issuer 配置、SCEP 外部签发接缝；[Apple 配置](../app/src/assembly/apple/config.rs)、[Apple 指南](../../docs/guides/apple-management.md) | 选择符合实际 SCEP 部署的 CA；现有受控签发接口提供签发，不由存档页替代 |
| Apple 逐设备 MDM 身份证书 | macOS MDM check-in/管理客户端身份；私钥由设备持有 | Apple SCEP 与 MDM 通道；[Apple certificate owner](../certificate/src/apple.rs) | 终端产钥、注册授权后签发；每台设备独立，续期继续由注册生命周期负责 |
| Agent 签发 CA / 信任链（计划） | Agent 专用身份签发；CA 私钥归服务端 | #2629/#2630 的 Agent profile 与认证接线 | 本模块可存档 CA/CSR；Agent profile、授权和激活由对应任务实现 |
| Agent 逐注册身份证书（计划） | Agent 后台服务设备身份；私钥留在终端 | rss-mdm-agent 当前日常请求仍使用 Bearer；`ca_pem` 仅用于服务器信任 | 后续终端生成 CSR、专用签发及 mTLS 激活；不在服务端集中生成终端私钥 |
| Apple mobileconfig 签名证书及链 | 签署配置描述文件；匹配私钥归服务端 ProfileSigner | `profile_certificate_file` / `profile_private_key_file`；[Apple 配置](../app/src/assembly/apple/config.rs) | 按组织的信任部署申请/签发，导入证书和匹配密钥；独立于 APNs 和设备身份证书 |
| APNs MDM 推送证书 | Apple 推送服务的 MDM topic 身份；对应私钥归服务端 | `apns_certificate_file` / `apns_private_key_file`、`apns_topic`；[Apple 指南](../../docs/guides/apple-management.md) | 本模块生成 CSR，交 MDM Vendor 签名，再到 Apple Push Certificates Portal 申请；用原账号与原证书续期，核对 topic 后人工替换 |
| MDM Vendor CSR 签名证书（可选） | 作为获准的 MDM Vendor 为客户的推送 CSR 签名；私钥由 Vendor 持有 | 外部 Vendor 流程；本项目没有独立 Vendor 签名服务 | 需 Apple Developer 项目授权；普通本地 CA 无法签出此身份。没有该身份时使用获准 Vendor 的流程 |
| PostgreSQL TLS 服务器证书 | 数据库服务端身份；私钥归数据库运维 | PostgreSQL `ssl_cert_file` / `ssl_key_file` | DB 所属组织/CA 签发；数据库运维人工替换；不要求导入数据库私钥 |
| PostgreSQL TLS 信任 CA | 服务验证数据库 HTTPS/TLS 主机身份；只需要公开 CA | 各数据库连接 `tls.ca_file` / VerifyFull；[安装配置](../../fixtures/mdm-config.example.json) | 导入实际 DB 的信任 CA，保留主机名校验；可与企业 HTTPS CA 相同，但不混用服务器私钥 |
| 软件源/下载产物私有 HTTPS CA（可选） | 下载客户端信任软件源；公开 CA，无需 CA 私钥 | [Software source model](../software-service/src/lib.rs)及产物来源的 `private_ca` | 使用来源服务器的真实 CA；能与企业 HTTPS 信任 CA 共用时只建立多个使用位置 |
| Windows 代码签名证书 | 签署 EXE/DLL/NSIS EXE，私钥归发布系统或硬件签名设备 | rss-mdm-agent 发布流程；本项不改安装格式 | 正式发布向代码签名 CA 申请；EV/不可导出密钥保存引用；自签不产生公共信任。开发产物可不签名，按现有验证范围交付 |
| macOS Developer ID Application | 签署 Agent/应用可执行程序；私钥归发布环境/钥匙串 | rss-mdm-agent macOS 发布与公证流程 | Apple Developer 申请，实际 CSR/钥匙串或平台要求的流程；导入允许导出的备份或只存证书引用 |
| macOS Developer ID Installer | 签署 PKG 安装包；私钥归发布环境/钥匙串 | rss-mdm-agent PKG 发布流程 | Apple Developer 独立 Installer 身份；不能以 Application 证书替代 |

### 哪些可以共用

- 同一 HTTPS 服务器证书可以用于多个服务，前提是 SAN、有效期、用途和私钥共享策略都合适；每个服务仍显式配置文件。可在一个存档条目中记录多个使用位置。
- 客户端的公开信任 CA 可以共用。Windows、Apple、Agent 的 CA 是否共用由各通道 profile、信任和吊销边界决定；同一 CA 不代表设备证书互相获得通道权限。本项不修改当前通道隔离。
- 同租户的全部存档材料共用一个**解锁密码**，不因此共用证书或私钥。

### 必须保持独立的身份

CA 与叶证书、HTTPS 服务器与设备客户端、APNs 与 mobileconfig/软件签名、Developer ID Application 与 Installer 分别有不同职责。各设备和 Agent 注册拥有独立私钥/身份；原生 MDM 私钥不复制给 Agent。

CSR 是申请材料，SCEP 是申请协议，PKI 是体系，均不列成一张证书。任务 Ed25519 签名公钥、`signing_keys`、WNS client secret、webhook secret、数据库密码、ABM/ADE token 和 Apple Account 凭据不属于证书存档的密码托管范围。

## 外部申请入口

- [Apple MDM Vendor CSR signing certificate](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/)：Vendor 身份的授权与申请。存档生成的普通 APNs CSR 仍需 Vendor 包装/签名；不要将普通 CSR 当成最终 Vendor 签名文件。
- [Apple Push Certificates Portal](https://identity.apple.com/pushcert/)：申请/续期 APNs MDM 证书。保留使用账号和证书归属记录，避免另建 topic 后破坏原设备关联。
- [Apple Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)：Application 与 Installer 分别申请；硬件/平台私钥由实际发布环境持有。
- [Windows ClientCertificateInstall CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/clientcertificateinstall-csp)：PFX/SCEP、设备/用户范围和 Atomic 配置。存档 SCEP 模板不替代原生注册授权。

公共 HTTPS 和 Windows 软件签名按所选 CA 的正式流程申请；服务提供 CSR/申请准备与归档，不承诺产生公共发行信任。自动续期、CRL/OCSP、CA 轮换编排和 Agent mTLS 不在本模块中，完整 PKI 按 #2639 的 P3 范围实施。

## 接口与验证

管理接口位于 `/api/v1/certificate-archive`。写入使用 `Idempotency-Key`，并通过 `operations/{id}` 查询原结果。接口类型、格式、参数和闭合错误以[源码](src/lib.rs)及 [HTTP owner](../management-http/src/certificate_archive/mod.rs)为准；不另维护第二份 wire schema。

T1 验证加密坐标、换密码后旧材料解密、真实签名/CSR/PFX 与匹配检查；`make t2 MODULE=certificate-archive.http` 使用真实 Identity、PostgreSQL、HTTP 验证权限、RLS、历史、重启锁定、会话隔离和到期提醒。实际验证记录留在 PR。
