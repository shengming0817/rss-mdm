# 候选构建与安装

## 构建 V4 候选

构建使用当前工作区源码，包含未提交修改、已加入 Git 索引的新文件及删除；源码路径由 workspace 成员与构建输入限定。范围内未跟踪文件默认拒绝，新增源码须先逐项检查并加入索引，不要求 commit 或 clean HEAD。复制前后核对文件内容与状态，变化则终止构建；candidate 记录实际复制输入的摘要，运行验收不依赖源码 checkout。构建机需要 Docker Buildx 和私有 Git 只读凭据。后端可独立发布；前后端一起交付时，额外提供不可变 rss-web MDM image ID/repository digest。

```sh
# 仅后端
python3 hack/release.py --output artifacts/candidate --git-auth-header-file /private/azure-header
# 前后端一起交付（选择新的输出目录）
python3 hack/release.py --output artifacts/combined --git-auth-header-file /private/azure-header --web-image "$MDM_UI_IMAGE_ID"
python3 hack/build_run.py -- python3 hack/candidate_smoke.py --candidate artifacts/candidate
```

授权头文件须为 owner 独占普通文件，只以 BuildKit secret 供依赖获取使用。构建从一次源码副本生成正式 OCI，复用正常缓存；失败不发布候选目录，已有输出不覆盖。

V4 候选包含 server.oci.tar、candidate.json、示例配置、deployment 下的角色 SQL、nginx 配置与 Agent 叶证书模板，以及普通构建记录。传入 `--web-image` 时另包含 identity-ui.image.tar 和 manifest 的 `ui` 信息，并保留前端镜像身份、运行用户和归档完整性检查；省略时不检查或归档前端。已有包含前端的 V4 候选仍可消费。manifest 固定实际镜像身份、归档摘要、平台、依赖提供者及全部部署输入摘要。恢复时先核验归档与部署输入，再 docker load；不从 tag 拉取替代品。V2 必须重新构建，没有兼容解析或转换器。

安装、smoke 与认证验收不要求 matching checkout、Git 元数据或 clean HEAD。把运行工具与候选放到独立目录也可执行，工具从候选目录读取角色和网关文件。候选摘要保护所交付内容的一致性，不替代分发渠道信任。

smoke 启动实际 OCI、自有 TLS PostgreSQL 与 HTTPS 网关，验证迁移、初始化、权限、重放、健康与关闭；不构建第二个消费者。仅后端候选使用固定 nginx 依赖提供 HTTPS API 代理，页面路径返回 404；包含前端的候选使用交付的前端镜像提供页面。浏览器认证验收要求包含前端，缺失时明确拒绝并提示使用 `--web-image` 重建。成功与资源清理完成后才发布 smoke.json/smoke.log，失败移除旧成功标记并保存脱敏诊断。真机 T3 另行提供。

## 全新实例安装

MDM 宿主使用同一份运行配置生成两份公开 bootstrap 输入：`ui.json` 的
`canonicalOrigin/oidcEnabled` 和 `mdm.json` 的 `canonicalOrigin/tenant`。
部署网关分别在 `/api/v1/identity-host/config.json`、`/api/v1/mdm-host/config.json` 精确提供这些文件，
不得填入凭据或另设租户权威。环境初始化与候选运行工具从 `product_origin`、`identity` 自动生成，
手工部署须将相同公开字段只读挂载到网关。

`/api/v1/mdm-candidate/workspace` 返回当前会话的真实模块导航提示；提示不授予权限。
Identity callback 固定 `/api/v1/identity/oidc/callback`，其它 API 保留后端路由和错误，不能落入 SPA。
这些宿主配置和 HTTP 接缝由后端验证；前端消费和页面验收由前端 owner 负责。

使用 candidate.json 固定的依赖和二进制 --describe 声明的安装单元。只接受空库或完全一致的当前安装记录；失败恢复见 [运维](operations.md)。

由数据库管理员创建专用数据库和 `mdm_owner`、`mdm_runtime`、`mdm_api`、`mdm_access` 基础角色。所有产品角色均禁止 SUPERUSER、BYPASSRLS 和高权继承；`mdm_owner` 需要该数据库与 public schema 的 CREATE 权限，但不持有 CREATEROLE。`mdm_api` 是组件 reader 的验证角色，不进入 serve 配置。

再按顺序安装候选目录 deployment/ 中的 `software-publication-roles.sql`、`flow-roles.sql`、`identity-roles.sql`、`commands-roles.sql`、`audit-roles.sql`。脚本创建的 NOLOGIN profile 保持为权限角色；仅对实际配置的连接角色启用 LOGIN 并设置独立秘密，不额外授予继承权限。Identity runtime/maintenance/audit worker 不继承 owner；owner 的准入检查所需切换关系由随附 SQL 设置。

Audit 与 Ledger 的组件 SQL 分别由 `mdm_audit_owner`、`mdm_ledger_owner` 安装，两个 owner 均为 NOLOGIN、NOSUPERUSER、NOBYPASSRLS。管理员须对目标数据库执行 `audit-roles.sql` 中的 CREATE 授权。四类产品运行角色只取得组件表 SELECT 和固定写函数 EXECUTE；产品恢复回执位于 `mdm_audit.receipts`，使用租户 RLS 和 SELECT/INSERT 权限。

`migrate` 使用 mdm_owner；`initialize` / `recover-password` 使用 mdm_identity_maintenance；`initialize-authorization` 使用 mdm_access 显式初始化一次产品授权；`serve` 只使用对应运行角色。安装会检查实际 runtime/maintenance 和 audit worker 权限，脚本成功不代表角色准入成功。

迁移输入含 database 和 installation；installation 固定 instance_id、target、lineage、epoch、所有租户及 audit_mode（plain 或 ledger，与运行配置 audit.mode 一致）。初始安装名单支持 1–1024 个不同租户；已有安装重放要求名单一致。安装按该模式授予 Identity audit worker 权限；Plain 不授予 Ledger 权限，Ledger 仅授予公开追加与验证所需权限。模式纳入安装记录，重放不得改变。初始化输入另含 tenant_id、principal_id、login、password_file；通过组件维护接口初始化，日常账户与 IdP 管理使用受保护公共 HTTP 接口。

~~~sh
docker load --input server.oci.tar
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE migrate --config /run/mdm/migrate.json
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE initialize --config /run/mdm/initialize.json
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE initialize-authorization --config /run/mdm/authorization.json
docker run --name rss-mdm --network host --mount type=bind,src=/private/mdm-runtime,dst=/run/mdm,readonly IMAGE serve --config /run/mdm/config.json
~~~

IMAGE 替换为 candidate.json 固定镜像身份。秘密和配置文件由 UID 10001 持有且权限 0600。安装目录与运行目录分开准备；镜像不嵌入配置或私钥。

## 桌面与 Agent 入口及服务器证书信任

网关加载部署方配置的服务器证书链与私钥。使用私有 CA 时，把签发该服务器证书的 CA 公共证书通过可信部署渠道分发到设备；CA 私钥留在部署端，不放入 Agent 配置、客户端安装包或前端静态资源。数据库连接的 `ca_file` 属于 PostgreSQL 信任，不复用为组织网关 CA。

桌面客户端的组织连接和私有 CA 部署输入放在构建/部署所用 `.env`：`RSS_MDM_ORIGIN` 对应本服务的 HTTPS `product_origin`，`RSS_MDM_TENANT_ID` 对应 `identity.tenant_id`，可选 `RSS_MDM_CA_FILE` 指向签发网关证书的单个 PEM CA 公共证书绝对路径。桌面构建时嵌入公共证书，仅对该 origin/tenant 生效，不读取系统执行服务的配置。Agent 的 `execution.json.origin` 必须使用 `agent_pki.endpoint.origin`，tenant 对应 `identity.tenant_id`；`ca_file` 信任该 Agent TLS 入口服务器证书的签发 CA，并把公共 CA 文件放到受保护的设备路径。桌面网关和 Agent 入口由同一 CA 签发时可以分发同一公共证书；分别签发时各自配置对应信任。Agent 的 `RSS_AGENT_ORIGIN` 与 `RSS_AGENT_CA_FILE` 分别配置该独立端点和 HTTPS CA；`RSS_AGENT_DEVICE_TRUST_FILE` 指向受保护的设备 purpose trust JSON。生成器要求 deployment V4，存量设备通信库先运行系统服务的 `--upgrade-device-pki` 显式升级，不能重建执行 journal 或重新注册设备。

服务端网关继续配置服务器证书链和私钥；它们不通过客户端 CA 环境变量传入。客户端 CA 留空时使用默认信任。CA 更新后桌面重新构建、Agent 重新加载配置，不修改系统证书库，也不跳过证书链或主机名校验。其它组织和个人 AI 连接不继承此 CA。

本仓开发环境生成的组织 CA 位于 `artifacts/dev-environment/development/ca.crt`；分发此公共文件即可，不分发同目录的 `ca.key`。浏览器控制台的信任仍由浏览器管理，客户端的应用内信任不会修改浏览器。

## 管理员密码恢复

准备独立 recover.json，沿用初始化配置的 installation、tenant_id 与既有 principal_id；`login` 必须为 null，`password_file` 指向新密码文件，database 使用 mdm_identity_maintenance。该操作轮换密码并撤销旧会话，不创建主体，也不恢复 MDM 业务授权。

```sh
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE recover-password --config /run/mdm/recover.json
```

配置与秘密为 owner 独占的普通 0600 文件，末级路径不得为符号链接；CA 为可读 PEM。maintenance 密码与恢复文件仅挂入 operator 容器，不挂入运行服务。恢复后验证新登录并按受控秘密管理流程处置临时密码文件。

## 运行配置与网络

运行配置从交付的 mdm-config.example.json 填写：实例、租户、产品域名、数据库地址、独立秘密、Windows 公开设备 trust、协议密钥和独立 TLS 输入。各数据库角色连接同一 MDM 数据库。OIDC 可不配置，本地认证无需参考应用或企业 IdP；企业接入使用产品自己的 `/api/v1/identity/oidc/callback`。账户坐标及旧、新主体不自动对应的边界见认证指南。

`identity.audit_worker` 必须配置独立 `mdm_identity_audit` 登录角色及秘密文件；host、port、name 必须与 `identity.database` 一致。安装器通过 Identity 公共 worker 授权接口赋予 consumer 与 Audit 权限，并通过 Ledger 的公开 SQL 接缝赋予追加能力；worker 不具有身份私表、producer、DDL 或直接审计表写权限。运行服务同时挂入 worker 密码，maintenance 密码仍仅归 operator。现有安装集合新增 `identity-audit-runtime-v1`，旧候选安装账本不会被静默升级。

所有运行模式（含 Apple-only 与 Agent-only）必须配置顶层 `native_protection_key_file`，例如 `"native_protection_key_file":"/run/mdm/native-protection.key"`。文件必须恰好包含 **32 字节原始随机密钥**，不是 hex/Base64/PEM 文本。首次部署可用 `umask 077; openssl rand 32 > /run/mdm/native-protection.key` 生成，由服务账户读取，文件权限限制为 0600。它是保护原生输入、回执及内容的持久身份；与 Windows 协议 `protection_key_file`、CA/TLS 私钥和审计 Ledger 密钥分别生成、配置和保管。所有访问同一部署数据的实例必须使用同一原始密钥；启动会检查数据库中的 tenant key identity，错误长度或换 key 拒绝启动。

运行配置和 `initialize-authorization` 配置必须显式填写 `audit`：Plain 为 `{"mode":"plain"}`；Ledger 为 `{"mode":"ledger","key_id":"部署提供的标识","key_file":"/run/mdm/audit-key"}`。密钥文件保存至少 32 字节的原始密钥，必须受文件权限保护；服务不自动生成、轮换或在错误时降级。所有运行角色使用 READ COMMITTED，恢复入口拒绝其他隔离级别。

Linux host 网络使回环浏览器监听与同机 HTTPS 网关配合；Windows 协议由产品直接终止 TLS/mTLS。采用 `deployment/nginx.conf`，替换产品域名和证书路径；覆盖 X-Forwarded-For 为真实 peer，清空 Forwarded，限制真实 peer 的登录频率、连接数、正文与读取时间。后端只在真实 TCP peer 匹配 trusted_gateway 后采用覆盖后的单一来源地址。不能把浏览器监听直接暴露或接到未受控转发器。

资源/计划/执行使用当前全新安装结构。产品配置中的 `flow.storage` 持有数据库连接及 target/lineage/epoch，`flow.publication` 持有发布数据库与 sources，`execution.database` 持有执行数据库连接；具体字段以[配置示例](../../fixtures/mdm-config.example.json)为准。旧综合 `management` 和混合 `tasks` 配置不再接受。`content.storage` 显式选择 `volume` 或启用版本控制的 HTTPS `s3`（[S3 配置示例](../../fixtures/mdm-content-s3.example.json)）；PostgreSQL 持有内容控制状态，`content` 配置共享内容仓，`task_signing` 单独配置任务签名；脚本任务要求两者齐备，软件入库/批准不需要任务私钥，原生协议的 `management` 监听配置保持独立。其它安装单元保持准确清单准入；设备 PKI 仅通过下述停写后的显式 `upgrade-pki` 转换，不提供通用旧库升级。

内容与网关的大小及时间预算必须一致配置。随附 nginx 配置仅为精确上传路由关闭 request buffering，示例正文上限 8GiB；普通请求继续保留原限制。内容目录须以可写持久卷提供给服务，签名秘密仍使用独立只读挂载。

## 时间线索引恢复

时间线索引是产品派生数据，`rss_audit` 持久事实仍是唯一来源。安装包含 timeline-service schema；旧 schema 继续按现有精确安装清单拒绝，不支持前缀升级。后台任务自动从 checkpoint 追赶，故障可见，恢复后继续读取原事实。

需要重建时先停止本安装的所有服务实例，由数据库 owner 在一个事务内设置目标租户上下文，删除该租户的 `mdm_timeline.facts`，将其 checkpoint 的 `position`、`source_through` 置为 -1、`healthy` 置为 true，并为 `generation` 设置新的 UUID。保留既有游标签名秘密和全部 Audit/Ledger 数据，再启动服务。旧游标因世代变化被拒绝；历史追赶完成前，API 明确返回覆盖进度。不得删除 Audit 事实、修补审计回执或改写迁移清单来恢复索引。

证书存档新增 `certificate-archive-schema-v1`，保持空库安装/准确安装记录重放，不升级旧候选账本。运行不需要存档主密码；存档通过现有租户授权管理授予独立权限，详见[证书目录](../../crates/certificate-archive-service/README.md)。

## Agent 专用 PKI

缺少 Agent 模板或必填配置的新部署须用当前源码重建候选。配置必须显式包含 `agent_pki`：未启用时使用 `{"mode":"disabled"}`，缺失、旧字段和未知成员拒绝。启用示例：

```json
"agent_pki": {
  "mode": "step_ca",
  "endpoint": {
    "listen": "0.0.0.0:9445",
    "origin": "https://agent.example.test:9445",
    "certificate_file": "/private/agent-tls.crt",
    "private_key_file": "/private/agent-tls.pk8"
  },
  "policy": {"grant_seconds": 86400, "platforms": ["windows", "macos"]},
  "trust_file": "/run/pki/agent-trust.json",
  "lifetime": {"mode":"standard"}
}
```

使用独立 purpose/issuer 数据库的 step-ca（固定验证版本 0.30.2），创建独立 `rss-agent` JWK provisioner。MDM 只加载其 RSA PKCS#8 DER 私钥、CA TLS 根证书和叶证书直接签发者的公开证书；CA 根/中间私钥及管理员凭据只归 CA 运维。私钥为服务账户独占读取的普通文件（0600/0400），禁止符号链接、公开权限、环境正文和源码提交。CA 网络只允许受控服务调用 `/sign`；MDM 固定 HTTPS origin、固定根、禁用代理和重定向。

在受控目录生成 RSA 2048–8192 位 provisioner 密钥，并从同一密钥导出 public JWK 与 PKCS#8 DER，保持 kid 一致。将 public JWK 导入 provisioner，**不要**上传私钥或设置 encryptedKey，以免 CA 对外分发签发凭据。用部署的 CA 管理凭据执行：

```sh
step ca provisioner add rss-agent --type JWK --public-key agent-provisioner.pub.json \
  --x509-template deployment/agent-leaf.tpl --disable-renewal --ssh=false \
  --x509-default-dur 8760h --x509-max-dur 8760h
```

模板唯一使用已验签 token 的 `.SANs`，固定 CN、非 CA、digitalSignature 和 clientAuth；不得换成 `.Insecure.CR` 或增加 serverAuth/其它目的。默认叶证书为 365 天。根 CA 可以设为十年；直接签发者须覆盖**完整**叶证书窗口，剩余不足拒绝签发，不截短期限。开发部署可显式改为 `{"mode":"development","days":3650}` 并将此 Agent provisioner 的 max/default 同步改至 87600h；上限 3650 天，直接签发者及根必须留出完整窗口。此设置不修改 Windows/Apple provisioner 的期限，也不启用自动 renewal。

服务端已经提供持久 Agent 授权、候选签发、真实 mTLS 激活、在线撤销及人工恢复；旧 Bearer 注册与业务入口退出。本次 Agent 系统服务已消费公开 trust、更新机器 CA 存储并持久续期；真实设备、安装方式和平台支持仍由独立 T3 验收。

Agent 注册与运行共用独立 Rust TLS 监听器，匿名 bootstrap 可无客户端证书，激活和运行必须有真实 TLS 客户端证书。不得经终止 TLS 的 HTTP 代理转发，不能信任证书头。浏览器 nginx 明确拒绝 `/api/v1/agent/`；Agent 直接访问配置的 endpoint origin。

## 设备 PKI 配置

所有设备 CA 路由由必填顶层 `device_pki` 持有，不保留旧 CA 字段别名或本地 Windows signer。每项固定 `purpose`（windows/apple/agent）、`issuer`（确切 issuer DER 的小写 SHA256）、CA HTTPS `origin`、`tls_root_file`、`provisioner`、`kid` 和 `provisioner_key_file`；Apple 另有同 CA origin 下的 `scep_url`。最多 48 项；每个 purpose/issuer 只有一条路线。准备新代次前先提供对应 provider，然后通过管理接口分发信任并激活。

Windows/Apple 的 `native_protocols.<purpose>.trust_file`、Agent 的 `agent_pki.trust_file` 是可信部署渠道提供的公开 JSON。格式来自 `rss-mdm-agent-wire::pki::Trust`：version=1，绑定精确 HTTPS origin、tenant、purpose、单调 revision，包含完整 issuer 集合与 active/prepared/verify_only 状态；每个 issuer 包含确切 DER digest、base64 DER certificate/root/issuer CRL/root CRL、provisioner/kid。恰好一个 active，最多 16 代。不能把 HTTPS/APNs/Profile 签名证书当作设备 CA。公共材料可读，但初始部署来源必须受保护；私钥文件只归对应 owner。

Windows 使用独立 `rss-windows` JWK provisioner 和随候选交付的 `deployment/windows-leaf.tpl`：

```sh
step ca provisioner add rss-windows --type JWK --public-key windows-provisioner.pub.json \
  --x509-template deployment/windows-leaf.tpl --disable-renewal --ssh=false \
  --x509-default-dur 2160h --x509-max-dur 2160h
```

其私钥按同一受保护 PKCS#8 流程配置到 Windows provider。模板只从已验签令牌的 `.Token.sub` 生成登记 CN，不复制 CSR 的主体、SAN 或扩展；服务端冻结原 CSR/SPKI 和授权登记，并校验签发结果。令牌中的 CSR 输入名称仅供 step-ca 的前置校验，原 CSR 指纹绑定仍必须验证。不要替换为默认模板或 `.Insecure.CR`。生产叶证书完整 90 天；开发时同步配置明确的有效期和 CA max/default。Docker 候选将 Windows 与 Agent 模板一并哈希交付，运行夹具也消费这份模板。

## 设备 PKI 升级

旧部署不能直接运行新 `migrate` 或继续使用旧配置。停止旧签发入口，先用旧可执行文件处理 Agent、Windows 与 Apple 的未知签发、待激活结果及续期；确认这些工作已完成，再停止所有旧写入实例。保存原 CA 公共链和仍需验证的 legacy issuer，并在 CA 运维侧用原密钥产生可验签的当前 CRL；旧 Windows 私钥退出宿主，只在受控离线 CRL 操作中保管。准备新的 active step-ca 代次及公开 trust，旧代次为 verify_only。

使用新镜像的 `upgrade-pki --config /run/operator/upgrade-pki.json`，输入包含 database、原完整 installation、target_config_file、profiles 和 trusts。先以相同字段（不含 profiles）写入受保护 prepare.json，执行 `umask 077; rss-mdm prepare-pki-upgrade --config /run/operator/prepare.json > /run/operator/upgrade-pki.json`。准备命令只读原数据库，从完整旧 manifest 和实际历史记录获取 previous，由 Windows/Apple 运行时同一 canonical 函数计算目标 current；操作员检查生成的集合。升级在连接和写入前重新读取 target_config_file，核对 tenant/instance、公开 trust 与全部 current，目标错误直接拒绝。profiles 是 Windows/Apple 旧稳定配置 hash 到新配置 hash 的显式替换集合；同 purpose 的目标配置必须一致，覆盖所有旧记录。trusts 覆盖每个实际使用的租户/purpose 及历史 issuer。升级只接受 exact 已完成的整个 pre-PKI 安装 manifest，检查并导入历史证书的签名、用途、登记映射和续期，原子写入新 PKI schema 和安装记录。过期/撤销证书可保留为历史记录，不能获得在线认证资格。未知提交后重跑会验证已完成的当前 manifest，不重复转换。

普通 `migrate` 的完整 manifest 准入保持不变；没有旧格式运行时解析、自动重签、备用本地 CA 或混合版本写入。迁移成功后更新各公开 trust/provider 输入，启动新宿主并通过[运维路径](operations.md#设备-pki-轮换与撤销)处理后续轮换。
