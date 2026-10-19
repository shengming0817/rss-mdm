# 候选构建与安装

## 构建 V5 候选

构建使用当前工作区源码，包含未提交修改、已加入 Git 索引的新文件及删除；源码路径由 workspace 成员与构建输入限定。范围内未跟踪文件默认拒绝，新增源码须先逐项检查并加入索引，不要求 commit 或 clean HEAD。复制前后核对文件内容与状态，变化则终止构建；candidate 记录实际复制输入的摘要，运行验收不依赖源码 checkout。构建机需要 Docker Buildx 和私有 Git 只读凭据。后端可独立发布；前后端一起交付时，额外提供不可变 rss-web MDM image ID/repository digest。

```sh
# 仅后端
python3 hack/release.py --output artifacts/candidate --git-auth-header-file /private/azure-header
# 前后端一起交付（选择新的输出目录）
python3 hack/release.py --output artifacts/combined --git-auth-header-file /private/azure-header --web-image "$MDM_UI_IMAGE_ID"
python3 hack/build_run.py -- python3 hack/candidate_smoke.py --candidate artifacts/candidate
```

授权头文件须为 owner 独占普通文件，只以 BuildKit secret 供依赖获取使用。构建从一次源码副本生成正式 OCI，复用正常缓存；失败不发布候选目录，已有输出不覆盖。

V5 候选包含 server.oci.tar、installer.oci.tar、rss-mdm-installer、candidate.json、示例配置、deployment 下的角色 SQL、nginx 配置与 Agent 叶证书模板，以及普通构建记录。传入 `--web-image` 时另包含 identity-ui.image.tar 和 manifest 的 `ui` 信息，并保留前端镜像身份、运行用户和归档完整性检查；省略时不检查或归档前端。V5 候选包含与服务镜像一致的 Linux 安装二进制，摘要单独绑定到 manifest；缺少当前契约的旧二进制候选必须重新构建。manifest 固定实际镜像身份、归档摘要、平台、依赖提供者及全部部署输入摘要。恢复时先核验归档与部署输入，再 docker load；不从 tag 拉取替代品。V2 必须重新构建，没有兼容解析或转换器。

安装、smoke 与认证验收不要求 matching checkout、Git 元数据或 clean HEAD。把运行工具与候选放到独立目录也可执行，工具从候选目录读取角色和网关文件。候选摘要保护所交付内容的一致性，不替代分发渠道信任。

smoke 启动实际 OCI、自有 TLS PostgreSQL 与 HTTPS 网关，验证迁移、初始化、权限、重放、健康与关闭；不构建第二个消费者。仅后端候选使用固定 nginx 依赖提供 HTTPS API 代理，页面路径返回 404；包含前端的候选使用交付的前端镜像提供页面。浏览器认证验收要求包含前端，缺失时明确拒绝并提示使用 `--web-image` 重建。成功与资源清理完成后才发布 smoke.json/smoke.log，失败移除旧成功标记并保存脱敏诊断。真机 T3 另行提供。

## 全新实例安装

Linux 单机安装由固定候选中的 `rss-mdm-installer install --config /absolute/private-input.json` 执行。宿主需要 systemd、Docker Engine/Compose、受信 TLS 入口及二进制运行依赖。安装器先保存稳定身份和秘密，再准备专用 PostgreSQL 数据库与受限角色、初始化独立平台/业务管理员、应用默认租户宿主。数据库引导连接只由部署操作员持有，服务容器不接收该凭据。

部署输入结构由 [安装输入](../../crates/app/src/setup/installation.rs) 持有。`database` 包含目标 `name` 和引导 `administrator` 连接；角色密码由安装目录生成。`deployment` 固定服务/网关镜像摘要及 TLS 材料；`additional_hosts` 列出后续租户可用的独立入口、监听和部署参数；当前单机模板为每个租户运行独立网关，HTTPS 端口和后端监听不得重复。没有可用槽位时保留原开通操作并显示 capacity，不另建租户或账户。槽位预留不可改绑，新增容量需追加配置并重启部署进程。

安装器将部署二进制复制到 root 独占安装目录，注册 `rss-mdm-deployer-<instance>.service`。该进程消费已有开通回执和领域期望版本，使用固定 Docker Compose 模板部署宿主；管理 HTTP 不接受任意命令或维护凭据。实例目录、原凭据、角色密码和固定 Ledger 密钥必须联合备份。重试使用原输入和原目录；密码或密钥丢失时恢复原材料，不重新生成替代身份。

### 单机部署设计与配置归属

单台 Linux 主机可承载 MDM 后端、HTTPS 网关、PostgreSQL、RustFS 和 step-ca；Identity 嵌入后端，真实 Windows/Mac 和独立交付的 Agent 在设备侧。该拓扑是部署与验收设计，不表示共享 CA、真机效果或高可用已通过验证。正式安装以本节安装器为入口，Compose 由[部署器](../../crates/app/src/setup/deployment.rs)生成；不另维护手工建租户、复制运行 JSON 的安装流程。

当前部署器为后端和网关使用 `network_mode: host`。管理 API 仅监听回环，`trusted_gateway` 与该监听 IP 相同；每个业务宿主拥有独立入口和不冲突的监听。新增业务租户使用完整开通 API 与预留的 `additional_hosts`，不能只改请求 tenant 或复制一份 JSON 冒充第二宿主。PostgreSQL、对象存储及 CA 的部署和持久目录由运维准备，不将它们的管理员凭据交给日常服务。

| 入口 | 路由与信任边界 |
|---|---|
| 控制台/管理 API | 组织 HTTPS origin → 受信网关 → 后端回环；前端需独立固定 MDM UI 镜像并验证实际页面与会话，仅后端候选不提供控制台 |
| Windows 注册与管理、Apple 管理、Agent 注册与运行 | 各自配置的 TLS 监听/origin，后端直接验证 TLS/mTLS；不能用代理头替代设备证书身份 |
| Apple SCEP | CA 的受控 HTTPS SCEP 路径；产品 challenge/notify 回调、CA TLS 信任、设备 SCEP 服务信任分别核对，不开放 CA 管理/签发路径给普通客户端 |
| PostgreSQL、RustFS、CA 管理 | 仅允许实际受控消费者访问；有独立服务证书、凭据与存储，不因同机部署关闭 TLS/主机名验证 |

Windows、Apple、Agent 共用一个 step-ca/root/issuer 是需要单独验收的部署选择。路由按用途和 issuer 区分，即使共用签发者也须保留独立用途模板、JWK/SCEP 凭据和三份用途绑定 trust；Agent bootstrap 另有自己的用途与前置条件。共享 CA 会扩大密钥泄露、CRL、数据库和停机的影响范围，不能直接继承当前按 purpose/issuer 隔离的 CA 基线结论。未验证时记录 blocked/unknown，详见[设备 PKI 运维](operations.md#设备-pki-轮换与撤销)。

| 输入或产物 | 当前 owner 与操作入口 |
|---|---|
| 镜像、网关 TLS、监听、数据库引导连接、可用宿主槽位 | 运维提供一份[安装输入](../../crates/app/src/setup/installation.rs)，冻结真实镜像 ID/digest；部署进程持有受限宿主执行权限，业务 API 不接收任意命令/路径 |
| instance/tenant/principal/operation、target/lineage、角色密码及安装保护材料 | 安装器生成并持久保存；首租户、独立平台/业务身份及授权由同一安装流程准备，重放不手工换 ID 或重置密码 |
| 运行快照、网关配置、公开宿主 JSON 与应用摘要 | 由安装/宿主应用 owner 派生；原操作冻结实际文件字节，不能编辑生成文件绕过期望版本及进程观察 |
| 用户、授权、注册设置、Group/Scope/Policy、软件与 Apple 组织 | 真实租户会话调用原领域 API；平台会话不自动获得业务数据权限，目录查询不成为第二个写 owner |
| APNs/Profile/Managed Apple Account、WNS、任务签名、SMTP、Webhook、S3 凭据 | 原领域 API 管理加密材料、版本与适用校验；部分变更直接生效，需运行应用的变更由部署 owner 执行，分别核对 requested/applied 与真实效果，见[运维指南](operations.md) |
| 设备 CA、OIDC 宿主准入、通道和恢复材料的部署设置 | 使用 `prepare-ca`、`configure-host` 及各领域接口；密钥轮换使用对应流程，不把原始 CA 私钥或任意内网准入交给租户 |
| 设备私钥、CSR、注册回执、Agent 本机 trust 与运行 journal | 由设备/注册 owner 生成持久保存；服务端只授权并分发所需公开材料，端侧部署由 [Agent 指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/local-service-lab.md&version=GBdevelop)维护 |

安装目录及数据库/材料秘密位于源码仓之外。私有目录、普通秘密文件和读取者权限按现有安装与 CA 规则设置，不使用符号链接或将整个部署根目录挂入运行容器。根私钥及离线根密码独立保管，在线 CA 只取得必要中间签发材料；`prepare-ca` 的管理凭据、SCEP 解密私钥不进入 MDM 运行宿主。服务 TLS 根、设备 issuer、Profile 签名身份和 APNs 身份分别校验，不能互相替代。

先安装可登录的基础管理宿主，再由授权会话导入组织材料，经原领域校验和受控宿主应用启用通道。缺少 APNs 等外部材料时明确保持相应通道关闭；材料保存、CA 准备通过、当前进程已加载与设备实际生效分别记录。S3 通过受限 `storage_profiles` 和下节连接流程准备，工作负载凭据不使用 RustFS root 身份，必须验证真实版本化及跨租户前缀拒绝。

### 对象存储开通与凭据更新

部署输入 `storage_profiles` 列出允许使用的 HTTPS S3 端点、region、bucket、基础 namespace 和 CA 文件。`rustfs_administrator` 只供部署进程执行固定 IAM 创建动作；导入其它 S3 凭据时提供 `boundary_verifier`，用于确认租户前缀之外的实际对象确实存在。管理 HTTP 只接受 profile 名称，不能提交任意端点或部署管理员材料。

业务管理员调用 `POST /api/v1/storage/connections`，携带 UUID `Idempotency-Key`，请求包含 `expectedRevision`、`profile`、`source`。`source.kind=generate` 在领域保护侧生成 RustFS 工作负载身份；`source.kind=import` 导入 `access_key`、`secret_key`，可选 `session_token` 和 `expires_at`，临时 token 必须有有效期限。材料加密入库后返回 202，供应方准备异步执行。`GET /api/v1/storage/connections` 投影当前目录；`GET /api/v1/storage/connections/operations/{id}` 查询原操作，未知提交不得换操作 ID 重建凭据。

部署进程在首次外部调用前固定端点、桶、命名空间与信任材料。自动创建验证 IAM 用户、策略和绑定；两条路径都验证 TLS、桶版本控制、真实版本化读写、精确版本删除以及对已确认存在的外部前缀对象的拒绝。失败保持原操作和凭据，可恢复重试；运行服务无权限自行标记供应方校验成功。桶须预先存在并启用版本控制。每个租户使用 `namespace/<tenant UUID>`；更新凭据不能改绑到其它桶或前缀。

合格版本进入宿主期望配置，经固定部署进程重启和真实 HTTPS 观察后才算应用。运行配置 `content.storage` 只引用材料 `revision`，不再接受 S3 端点或凭据文件。旧有效版本可支撑失败回退；过期或撤销材料在实际内容操作时被拒绝。资格回执是当次验证证据，不代表供应方永久健康。



MDM 宿主使用同一份运行配置生成两份公开 bootstrap 输入：`ui.json` 的
`canonicalOrigin/oidcEnabled` 和 `mdm.json` 的 `canonicalOrigin/tenant`。
部署网关分别在 `/api/v1/identity-host/config.json`、`/api/v1/mdm-host/config.json` 精确提供这些文件，
不得填入凭据或另设租户权威。环境初始化与候选运行工具从 `product_origin`、`identity` 自动生成，
手工部署须将相同公开字段只读挂载到网关。

`/api/v1/mdm-candidate/workspace` 返回当前会话的真实模块导航提示；提示不授予权限。
Identity callback 固定 `/api/v1/identity/oidc/callback`，其它 API 保留后端路由和错误，不能落入 SPA。
这些宿主配置和 HTTP 接缝由后端验证；前端消费和页面验收由前端 owner 负责。

原生采集持久恢复采用当前 execution schema；旧安装清单拒绝接入，无原地转换或双读。重新安装须使用独立空库，安装器不会自动清理已有数据库。

使用 candidate.json 固定的依赖和二进制 --describe 声明的安装单元。接受空库或完全一致的当前安装记录；失败恢复见[运维](operations.md)。

由数据库管理员创建专用数据库和 `mdm_owner`、`mdm_runtime`、`mdm_api`、`mdm_access` 基础角色。所有产品角色均禁止 SUPERUSER、BYPASSRLS 和高权继承；`mdm_owner` 需要该数据库与 public schema 的 CREATE 权限，但不持有 CREATEROLE。`mdm_api` 是组件 reader 的验证角色，不进入 serve 配置。

再按顺序安装候选目录 deployment/ 中的 `software-publication-roles.sql`、`flow-roles.sql`、`identity-roles.sql`、`commands-roles.sql`、`audit-roles.sql`。脚本创建的 NOLOGIN profile 保持为权限角色；仅对实际配置的连接角色启用 LOGIN 并设置独立秘密，不额外授予继承权限。Identity runtime/maintenance/audit worker 不继承 owner；owner 的准入检查所需切换关系由随附 SQL 设置。

Audit 与 Ledger 的组件 SQL 分别由 `mdm_audit_owner`、`mdm_ledger_owner` 安装，两个 owner 均为 NOLOGIN、NOSUPERUSER、NOBYPASSRLS。管理员须对目标数据库执行 `audit-roles.sql` 中的 CREATE 授权。四类产品运行角色只取得组件表 SELECT 和固定写函数 EXECUTE；产品恢复回执位于 `mdm_audit.receipts`，使用租户 RLS 和 SELECT/INSERT 权限。

`migrate` 使用 mdm_owner；`initialize` / `recover-password` 使用 mdm_identity_maintenance；`initialize-authorization` 使用 mdm_access 显式初始化一次产品授权；`serve` 只使用对应运行角色。安装会检查实际 runtime/maintenance 和 audit worker 权限，脚本成功不代表角色准入成功。

迁移输入含 database 和 installation；installation 只固定 instance_id、target、lineage 和 audit_mode（plain 或 ledger，与运行配置 audit.mode 一致）。安装创建唯一保留管理租户及 epoch=1，不创建账户、密码或权限；重放只核稳定安装身份、保留管理租户绑定、完整当前 schema 和运行权限，不比较租户全集，不改租户 epoch。安装按 audit mode 授予 Identity audit worker 权限，模式不能随重放改变。

新增租户统一使用平台会话调用 `POST /api/v1/tenant-administration/provisionings`，包含 `name`、`administratorLogin`、`administratorPassword`，并提供 UUID `Idempotency-Key`。返回可查询开通回执；202 表示管理员或宿主阶段尚未完成，不能解释为租户已启用。旧裸创建 HTTP 入口与 `tenant-create` 命令已移除。元数据维护、查询和追加管理员保留独立用途。

下列维护命令由实际 `mdm_owner` 登录连接执行，使用 `--config /absolute/private-config.json`，公共输入为 database 和稳定 installation：

| 命令 | 其它输入 | 输出与约束 |
|---|---|---|
| `tenant-get` | tenant_id | 当前租户详情，包括 initial_epoch、current_epoch、name、notes、revision、deletable、management |
| `tenant-list` | 无 | 所有未删除租户详情，按 UUID 排序，最多 1024 个业务租户与 1 个管理租户 |
| `tenant-update` | tenant_id、expected_revision、operation_id；可选 name、notes | 全量替换元数据；省略或 null 清空字段；成功时 revision 加一，即使值未改变 |
| `tenant-delete` | tenant_id、expected_revision、operation_id | 仅允许删除从未声明使用的租户，revision 加一；保留墓碑、epoch、默认设置和回执 |
| `tenant-operation-status` | operation_id | 返回 committed 与原始 receipt，或 not_found 与 null |

tenant_id 与 instance_id 须为非空规范小写 UUID；operation_id 须为非空 UUID；initial_epoch 和 expected_revision 须为正整数。name 可为 null，否则最多 128 个 Unicode 字符且不能全为空白；notes 可为 null，否则最多 2048 个字符。元数据不控制权限或宿主绑定。tenant_id、installation 和 epoch 不通过更新命令修改；current_epoch 由 RSS fencing 持有。

容量按未删除业务租户计数，管理租户不计入 1024 上限，且不能更新、删除或作为业务宿主租户。删除释放容量，但租户 ID 永不复用。删除后新 get/update/delete 返回 NotFound，列表隐藏墓碑；没有强制删除、恢复、数据清扫、旧命令别名或旧 schema 迁移。旧安装与当前安装清单不匹配时拒绝运行，必须重新安装当前契约。

create/update/delete 的 operation_id 共用一个全局命名空间。同一操作、同一规范业务输入返回原始回执，包括删除后及后续元数据/epoch 改变后的重放；同操作异参、重复租户、过期版本或版本溢出拒绝。回执为 `{operationId, action, result}` 的提交时快照；数据库凭据不进入持久化业务请求。

提交确认丢失、命令超时或成功后连接清理失败时，保留 operation_id，使用 `tenant-operation-status` 查询回执，或用原输入重放。查询与写入共用安装级锁；锁等待失败不能解释成没有提交。`not_found` 仅表示查询取得锁后未发现已提交回执，不取消后来发起的操作。

账户初始化、授权初始化和 serve 在后续工作前，通过受限数据库能力核验安装身份、当前期望 epoch 和租户状态，并提交永久 used 标记。标记不改变元数据版本，后续初始化或启动失败也不会恢复可删除性。删除与首次使用共用安装锁；先删除则使用被拒绝，先声明使用则删除返回 InUse。运行角色仅有该固定函数 EXECUTE，不能直接更新租户表。

账户初始化输入另含 tenant_id、expected_epoch、principal_id、login、password_file；授权初始化沿用 user.tenantId 并显式提供 expectedEpoch。两者从数据库核验登记及当前 epoch，使用各自受限角色。日常账户与 IdP 管理使用受保护 HTTP 接口。

通过 `tenant-list` 找到 `management=true` 的唯一管理租户。部署方沿用现有 `initialize` 配置，把 tenant_id 填为该 ID、expected_epoch 填 1，显式创建初始账户；随后用同一账户执行 `initialize-authorization`，其 user.tenantId 也填该 ID。初始规则授予租户 CRUD、创建租户管理员、账户管理与授权读写，不授予设备业务权限。

账户、IdP 和业务授权统一保存在 authorization rules 中。旧 `identity_management` 配置已删除，提供该字段会被拒绝。管理租户初始主体持有 `identity_accounts_manage`、`authorization_read/write` 以及租户 CRUD、`tenant_administrator_create`；前三项受防锁死保护，其余可分别委派或撤销。管理租户不支持 IdP/联合登录。业务租户的账户与 IdP 管理分别使用 `identity_accounts_manage`、`identity_providers_manage`，规则变化即时生效。

可选 `tenant_administration` 配置启用租户管理 HTTP API；完全省略时七个入口均不挂载，配置不完整或权限不匹配会拒绝启动：

~~~json
{
  "tenant_administration": {
    "registry_database": {"host":"db","port":5432,"name":"mdm","user":"mdm_tenant_registry","password_file":"/run/mdm/registry-password","ca_file":"/run/mdm/ca.crt"},
    "provisioning_database": {"host":"db","port":5432,"name":"mdm","user":"mdm_identity_provisioning","password_file":"/run/mdm/provisioning-password","ca_file":"/run/mdm/ca.crt"},
    "fingerprint_key_file":"/run/mdm/tenant-operation-key"
  }
}
~~~

密钥文件为安装级固定 32 字节随机密钥，使用与其它秘密相同的文件保护；重启必须保留，用于请求 HMAC 指纹，不保存明文密码或快速密码摘要。两种数据库角色按安装 SQL 创建，仅赋予各自的 registry、provisioning、授权读取和审计权限；不要使用 mdm_owner 或维护凭据替代。管理 API 复用当前 HTTPS、origin、cookie、CSRF 与管理租户登录。

| 方法与路径（前缀 `/api/v1/tenant-administration`） | 请求 / 结果 |
|---|---|
| POST `/provisionings` | `name`、`administratorLogin`、`administratorPassword`；返回完整开通操作 |
| GET `/provisionings` | 开通操作分页列表；`after` 为上一页游标，`limit` 为 1–1000（默认 100）；返回 `items` 和 `nextAfter` |
| GET `/provisionings/{operationId}` | 查询原开通操作与当前恢复阶段 |
| GET `/tenants` | 未删除租户列表，包含保留管理租户 |
| GET `/tenants/{tenantId}` | 当前元数据 |
| PUT `/tenants/{tenantId}` | `expectedRevision` 与替换元数据 |
| DELETE `/tenants/{tenantId}` | JSON `expectedRevision` |
| POST `/tenants/{tenantId}/administrators` | `login`、`password` |
| GET `/operations/{operationId}` | 原始已提交回执；不存在为 404 |

所有写入仅从 `Idempotency-Key` 读取规范 UUID；JSON 拒绝未知字段。开通操作尚未完成时返回 202，完成及完成后的重放返回 200；其它写入成功及重放返回 200。回执统一为 `{operationId,action,result}`；CLI 的回执采用同一格式，字段使用 camelCase。相同操作号请求内容不同返回 409，重放保持最初结果与操作者，后续修改不改变回执。

创建管理员要求管理租户 `tenant_administrator_create` 及 300 秒内认证。服务生成新主体，原子写入账户、目标租户全部业务/设备 AllDevices 与账户/IdP 管理权限、审计和回执；不授予安装级租户管理权限，也不签发目标租户会话。可持续添加多个管理员；重复登录名返回 409，不重置或接管已有账户。重放会复核操作者当前会话与权限，但不重新赋权。开始账户初始化前永久登记首次使用，失败也不恢复可删除性。

每个宿主通过 identity.tenant_id 和 flow.storage.epoch 绑定一个已登记业务租户，启动核验安装身份、audit mode、登记和期望 epoch。同库其它租户使用各自合法绑定宿主；新增登记不自动切换已有宿主。

新实例使用前述 `install` 单输入入口，后续租户使用完整 provisionings 资源。`migrate`、`initialize` 与 `initialize-authorization` 保留给各自维护用途，不能组合成另一条公共租户创建路径。安装器按固定镜像身份准备运行输入，秘密由 UID 10001 持有且权限 0600；镜像不嵌入配置或私钥。

## 客户端入口与服务器证书交付

网关加载部署方配置的服务器证书链与私钥。使用私有 CA 时，把签发该服务器证书的 CA 公共证书通过可信部署渠道分发到设备；CA 私钥留在部署端，不放入 Agent 配置、客户端安装包或前端静态资源。数据库连接的 `ca_file` 属于 PostgreSQL 信任，不复用为组织网关 CA。

服务端向桌面客户端部署方提供 HTTPS `product_origin`、绑定的 `identity.tenant_id` 和签发网关证书的 CA 公共证书。桌面构建与组织信任配置由 [rss-mdm-agent 桌面开发指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/desktop-development.md&version=GBdevelop) 维护。

服务端向 Agent 部署方提供独立的 HTTPS `agent_pki.endpoint.origin`、绑定的 `identity.tenant_id`、签发该 TLS 入口服务器证书的 CA 公共证书，以及受保护渠道交付的设备 purpose trust。桌面网关和 Agent 入口分别核对对应的服务器证书信任；由同一 CA 签发时可以分发同一公共证书。HTTPS 信任与设备 purpose trust 分别校验，不能相互替代，也不跳过证书链或主机名校验。Agent 的配置生成、安装、升级与恢复由 [rss-mdm-agent 服务部署指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/local-service-lab.md&version=GBdevelop) 唯一维护。

服务端网关配置服务器证书链和私钥；向客户端交付的信任材料只含公共证书。

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

所有运行模式（含 Apple-only 与 Agent-only）必须配置顶层 `native_protection`，包含 `active_file`、`historical_files` 与 `fingerprint_file`。每个文件恰好包含 32 字节原始随机密钥，权限 0600；不是 hex/Base64/PEM 文本。全新安装分别生成加密钥与比较钥。`active_file` 只用于新密文，最多保留 15 个历史解密钥，按密文中确切 key ID 读取。`fingerprint_file` 维持原有请求、材料与设备比较身份，不能随密文重加密替换。Ledger、Windows 协议保护材料和恢复凭据专用钥集合仍分别保管。旧 `native_protection_key_file` 配置不再接受，也不提供转换入口。

运行配置和 `initialize-authorization` 配置必须显式填写 `audit`：Plain 为 `{"mode":"plain"}`；Ledger 为 `{"mode":"ledger","key_id":"部署提供的标识","key_file":"/run/mdm/audit-key"}`。密钥文件保存至少 32 字节的原始密钥，必须受文件权限保护；服务不自动生成、轮换或在错误时降级。所有运行角色使用 READ COMMITTED，恢复入口拒绝其他隔离级别。

Linux host 网络使回环浏览器监听与同机 HTTPS 网关配合；Windows 协议由产品直接终止 TLS/mTLS。采用 `deployment/nginx.conf`，替换产品域名和证书路径；覆盖 X-Forwarded-For 为真实 peer，清空 Forwarded，限制真实 peer 的登录频率、连接数、正文与读取时间。后端只在真实 TCP peer 匹配 trusted_gateway 后采用覆盖后的单一来源地址。不能把浏览器监听直接暴露或接到未受控转发器。

资源/计划/执行使用当前全新安装结构。产品配置中的 `flow.storage` 持有数据库连接及 target/lineage/epoch，`flow.publication` 持有发布数据库与 sources，`execution.database` 持有执行数据库连接；具体字段以[配置示例](../../fixtures/mdm-config.example.json)为准。旧综合 `management` 和混合 `tasks` 配置不再接受。`content.storage` 显式选择 `volume` 或启用版本控制的 HTTPS `s3`（[S3 配置示例](../../fixtures/mdm-content-s3.example.json)）；PostgreSQL 持有内容控制状态，`content` 配置共享内容仓，`task_signing` 单独配置任务签名；脚本任务要求两者齐备，软件入库/启用不需要任务私钥，原生协议的 `management` 监听配置保持独立。本版本按全新安装交付，安装清单只持有当前完整 schema。

内容与网关的大小及时间预算必须一致配置。随附 nginx 配置仅为精确上传路由关闭 request buffering，示例正文上限 8GiB；普通请求继续保留 16KiB。管理专属路由的网关上限对应 `management-http/src/body_policy.rs`：Policy/Resource 8MiB、设备 operations 16MiB、PKI rotation/CRL 64MiB、signing recovery 256KiB、Entra policy 128KiB、证书导入及授权规则/用户组 2MiB、软件目录及 Agent 包写入口 1MiB；应用继续按方法执行精确预算与 DTO 校验。内容目录须以可写持久卷提供给服务，签名秘密仍使用独立只读挂载。

## 时间线索引恢复

时间线索引是产品派生数据，`rss_audit` 持久事实仍是唯一来源。当前全新安装包含 `timeline-service-schema-v2`，checkpoint 不持有后台健康状态；旧安装清单不能用于当前候选，启动和安装校验会拒绝不匹配的清单，不提供旧结构自动升级。授权访问设备时间线或管理审计检索时才从 checkpoint 有界追赶，故障返回不可用，后续请求重新尝试。

需要重建时先停止本安装的所有服务实例，由数据库 owner 在一个事务内设置目标租户上下文，删除该租户的 `mdm_timeline.facts`，将其 checkpoint 的 `position`、`source_through` 置为 -1，并为 `generation` 设置新的 UUID。保留既有游标签名秘密和全部 Audit/Ledger 数据，再启动服务并通过授权查询触发追赶。旧游标因世代变化被拒绝；历史追赶完成前，API 明确返回覆盖进度。不得删除 Audit 事实、修补审计回执或改写迁移清单来恢复索引。

安装包含 `certificate-archive-schema-v1`。运行不需要存档主密码；存档通过现有租户授权管理授予独立权限，详见[证书目录](../../crates/certificate-archive-service/README.md)。

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
  "trust_file": "/run/pki/agent-trust.json",
  "lifetime": {"mode":"standard"}
}
```

启用 Agent 时，`task_signing` 只引用已持久化权威的 `revision`；私钥由任务签名 owner 加密保管，不再接受 private_key_file、key_id 或 trusted_keys 启动字段。注册 owner 使用同一受控签名权威及独立签名域签发配置文件；Agent 包仍须预置相应公开验证密钥。授权期限和平台启用设置只由数据库后台接口持有，旧 `agent_pki.policy` 被拒绝，见 [Agent 接入](../guides/agent-integration.md)。

使用独立 purpose/issuer 数据库的 step-ca（固定验证版本 0.30.2），创建独立 `rss-agent` JWK provisioner。MDM 只加载其 RSA PKCS#8 DER 私钥、CA TLS 根证书和叶证书直接签发者的公开证书；CA 根/中间私钥及管理员凭据只归 CA 运维。私钥为服务账户独占读取的普通文件（0600/0400），禁止符号链接、公开权限、环境正文和源码提交。CA 网络只允许受控服务调用 `/sign`；MDM 固定 HTTPS origin、固定根、禁用代理和重定向。

在受控目录生成 RSA 2048–8192 位 provisioner 密钥，并从同一密钥导出 public JWK 与 PKCS#8 DER，保持 kid 一致。将 public JWK 导入 provisioner，**不要**上传私钥或设置 encryptedKey，以免 CA 对外分发签发凭据。用部署的 CA 管理凭据执行：

```sh
step ca provisioner add rss-agent --type JWK --public-key agent-provisioner.pub.json \
  --x509-template deployment/agent-leaf.tpl --disable-renewal --ssh=false \
  --x509-default-dur 8760h --x509-max-dur 8760h
```

模板唯一使用已验签 token 的 `.SANs`，固定 CN、非 CA、digitalSignature 和 clientAuth；不得换成 `.Insecure.CR` 或增加 serverAuth/其它目的。默认叶证书为 365 天。根 CA 可以设为十年；直接签发者须覆盖**完整**叶证书窗口，剩余不足拒绝签发，不截短期限。开发部署可显式改为 `{"mode":"development","days":3650}` 并将此 Agent provisioner 的 max/default 同步改至 87600h；上限 3650 天，直接签发者及根必须留出完整窗口。此设置不修改 Windows/Apple provisioner 的期限，也不启用自动 renewal。

服务端已经提供持久 Agent 授权、候选签发、真实 mTLS 激活、在线撤销及人工恢复；旧 Bearer 注册与业务入口退出。Agent 通过公开 HTTP API 消费设备信任与 PKI 生命周期，设备侧部署操作见上文链接的 rss-mdm-agent 服务部署指南；真实设备、安装方式和平台支持由独立 T3 验收。

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

### 恢复凭据密钥与接收证书

启用恢复凭据时配置顶层 `recovery_credentials`：

```json
{
  "active_key": "recovery-2026",
  "key_files": { "recovery-2026": "/run/mdm/recovery.key" },
  "active_recipient": "接收证书DER的SHA256小写十六进制指纹",
  "recipients": [{
    "certificate_file": "/run/mdm/recovery-recipient.crt",
    "private_key_file": "/run/mdm/recovery-recipient.key"
  }]
}
```

每个密钥文件恰好 32 个随机原始字节，私密文件权限为 0600。凭据密钥、接收 RSA 私钥、现有 native protection 密钥及 APNs/身份密钥分别生成与保管。接收证书和私钥必须匹配，RSA 至少 2048 位。FileVault 使用该证书接收 CMS，Agent 使用其公钥包裹 AES-GCM 数据密钥；不在客户端配置服务端私钥。未配置时不开放恢复凭据接口或派发该类 Agent 任务，macOS 锁定 PIN 托管也不可用。


### Webhook 宿主输入

顶层 `webhooks` 是必填闭合配置，示例中的空 networks 表示没有获准的接收端。
recovery_database 使用独立登录角色，具备 `mdm_webhook_operator` 的能力；按现有角色文件先部署
`webhook-roles.sql`，密码由部署秘密提供，不与访问或投递角色混用。恢复能力不暴露原始 runtime。

Webhook 密钥由 `/api/v1/webhooks/materials` 的领域权威加密持久化，接收端持钥确认后才能激活。安全交付、确认与旧签名退出见[Webhook 材料运维](operations.md#出站-webhook-签名材料)。运行配置不接受 keys/current_file/retiring，修改旧文件不能覆盖数据库材料。

每条 networks 配置包含 tenant、reference、hostname、port、addresses（IP:port）、cidrs 和 ca_files。
所有地址端口须匹配，地址须全部在允许 CIDR 内；CA 为 PEM。首版 DNS 策略为宿主固定地址快照，
adapter 按批准 IP 连接并验证原 hostname；地址变更需更新配置并重启。可显式允许企业内网。
不接受 URL 凭据、query、fragment，不跟随重定向或使用环境代理。

这些配置只描述允许范围；管理员仍须创建并明确启用订阅。访问池的 storage target、lineage 和
execution epoch 来自原宿主配置，在连接建立时固定；源事件复用 RSS 正式 SQL Outbox append 与
原 Audit 事务原子提交，失败不会触发事务后的直接 HTTP。新增组件迁移由既有 installer 执行。

### 固定候选的完整安装资格

`python3 hack/candidate_installation.py /absolute/candidate` 在独立 Linux 节点中消费候选的安装器镜像与服务镜像，使用真实 systemd 和 Docker daemon。节点以受限用途的 privileged 容器提供内核能力，不挂载宿主 Docker socket 或产品源码；测试 PostgreSQL、TLS 私钥和所有租户宿主均在节点内生成并随节点清除。宿主内核必须支持嵌套 Docker 与 systemd/cgroup；不满足时结果是资格缺失，不能将模拟 systemctl 或仅运行应用容器算作安装通过。

安装资格检查单输入安装、原凭据及 Ledger 密钥不变的重复安装、平台与业务的独立主体及真实登录、第二租户宿主、原开通操作重放及宿主租户隔离。成功记录 `installation-result.json` 绑定服务 OCI 摘要和平台，只有清理成功后才发布。协议/浏览器的 `candidate_smoke.py` 使用合法业务预置数据，独立证明原生协议与会话消费；它不承担完整开通证明。发布验收必须同时保留两种结果，真实设备资格仍由独立 T3 提供。

Native 保护轮换重加密运行凭据及 Apple 的 ADE、账户开通、设备令牌、命令和 DDM 证据行，不修改逻辑版本或重放 MAC。不可变内容对象、已有执行快照、证书归档以及历史备份仍可能依赖旧读取钥；因此本入口保留旧钥，未提供可绕过这些保留条件的删除动作。历史读取钥最多 15 份，达到上限会明确拒绝继续轮换，须完成对应历史数据和备份退出后再处理，不能删除旧钥冒充完成。

当前冷备/恢复操作要求部署侧 PostgreSQL 管理员为 superuser，并在停宿主或撤销 CONNECT 之前检查；该连接只交给离线部署操作员。它用于停写后重新连接、检查全部会话和原角色恢复，不能下发给业务服务。普通运行账户仍保持既有最小权限。

`configure-host channels` 不允许删除已经建立身份的 Windows/Apple 配置，避免重新启用时更换固定 fingerprint 或 identity seed。未配置通道可保持关闭；已配置材料过期或撤销时由领域运行校验降为不可用，更新仍沿原身份进行。

## 真机验收清单与证据

本节提供部署后的执行清单，不是自动判定器或已通过记录。正式 T3 的需求及稳定编号以 [PRD 产品验收](../product/rss-mdm-prd.md)第 10 节为准，独立任务先冻结本轮发布能力、必要场景、真实设备矩阵及故障范围。安装资格、readiness、协议 smoke、浏览器合成数据和已有 T2 均不能替代真实终端效果；不要求每个文档 PR 执行完整真机矩阵。

### 输入就绪与范围冻结

- 保存候选 manifest 摘要、后端/UI/Agent 制品实际镜像或包摘要、依赖 lock 和实际镜像身份、目标 Linux/CPU、Docker/Compose 版本。含控制台的验收必须使用真实 MDM 前端；Agent 包按平台提供正式签名/公证及匹配 wire 和信任材料。
- 从设备网络检查域名、公开端口、TLS 完整链、主机名及设备时间；从实际服务身份检查 PostgreSQL/RustFS/CA TLS、权限、持久目录与可恢复空间。容器内部可达不代表设备可达，不使用跳过证书验证的参数。
- 按所选能力提供真实 APNs/Profile、ABM/ASM/Entra/IdP 等组织资格、CA 模板/CRL/webhook 和受控签名材料。冻结设备 OS edition/build、架构、注册方式、用户/系统执行身份、浏览器及 Agent 版本；不从一次注册推断所有平台或权限组合可用。
- 准备平台管理员、独立业务管理员、只读/受限账户及合法第二租户宿主；通过领域 API 发布测试资源、软件版本、Group/Scope/Policy。安装器不制造业务成功数据，跨租户场景不能只修改请求中的 tenant。
- Windows/macOS 的服务、桌面/helper 及 PowerShell、osquery、Node/worker 等运行依赖按实际 Agent 包和所选动作准备；它们属于端侧，不能误列为服务器常驻容器。
- 每项能力在开测前明确 required 或 excluded，写明需求编号与理由；缺组织资格、设备或实现时对必选项记 blocked/unknown，不以临时改为 excluded 获得通过。输入变化开新轮次并重测受影响项。

### 真实闭环与反例

| 验收域 | 必须观察的结果与边界 |
|---|---|
| 入口与会话 | 设备网络上的真实页面、登录/刷新/退出、Cookie/CSRF；只读/无权限账户拒绝且无业务副作用 |
| 安装与租户开通 | 独立平台/首业务身份和合法宿主；第二租户完整开通；失败或容量不足沿原操作恢复，跨租户数据、操作与对象前缀均被拒绝 |
| Windows 原生 | 真实注册、设备证书及认证签入、原生采集进入产品资产；至少一项本轮支持的配置/命令有终端效果 |
| Apple 原生 | Profile 签名、SCEP challenge/notify、mTLS Authenticate/TokenUpdate、APNs 唤醒以及 Mac 上的命令/采集效果 |
| Agent Windows/macOS | 各平台真实签名包安装、登记与证书激活、采集报告、任务信任 ACK、签名任务领取/执行/结果与终端效果；重启后信任与身份持续有效 |
| 软件与对象存储 | 上传/冻结版本、RustFS 确切对象版本及摘要、设备下载/安装/版本检测；重启后原版本仍可读，错误摘要和被撤销凭据明确失败 |
| 内容边界 | 按本轮支持范围验证 Range、分块/多段上传、重放和内容完整性；失败不发布半成品，租户前缀之外访问被拒绝 |
| 策略与资产闭环 | Group/Scope/Policy、三类采集和合规按需求产生分配、设备效果及投影；旧结果/空值/来源冲突不误覆盖或误删，不把服务端入队当作设备完成 |
| 跨通道与结果未知 | MDM 与 Agent 的重复副作用保护；超时、断网、晚到结果和重启沿原身份恢复，未知操作不自动换 ID 或双发 |
| CA 与撤销 | 各用途模板/期限/凭据正确，跨用途证书不能取得设备身份；撤销持久生效并在签名 CRL 实际发布，既有 TLS/恢复会话仍受当前凭据校验 |
| 共享 CA 专项 | 选择共用 CA 时分别验证三用途签发、SCEP/JWK、共享 CRL 传播、单用途撤销与其它合法用途继续工作；保留隔离基线之外的独立结果 |
| 故障与联合恢复 | 服务/宿主重启、PG/CA/RustFS 不可用、原操作续跑及同址冷恢复；原账户、设备凭据、密钥、对象版本和审计关联可核验，见[单机恢复边界](operations.md#单机部署的重启与恢复边界) |

### 按发布能力补齐的外部条件

| 能力 | 真实输入与追加验证 |
|---|---|
| OIDC / Windows Entra | 真实 issuer/组织、批准的回跳与网络；宿主准入由部署方配置，租户 provider/Entra policy 经领域 API；验证认证、权限映射和对端故障 |
| WNS | 真实 PFN/SID/secret 经 WNS API 校验和宿主应用，验证设备实际唤醒；OAuth 成功或轮询成功不能代替推送效果 |
| ADE / Managed Apple Account | 真实 ABM/ASM 组织、设备资格、token/映射和账户签名材料，经组织/材料 API；验证真实注册、到期及恢复，合成 fixture 不替代组织资格 |
| MDM→Agent / Agent→MDM | 已签名 Agent 包、bootstrap 用途 trust/provider/webhook 与真实注册入口；验证原生安装/系统确认、引导交换、激活与清理，opened 不等于注册完成 |
| WinGet / Brew 私有发布 | 受控来源、仓库/产物、访问身份及具备相应执行能力的实际 Agent 包；按声明验证原生源、架构/上下文和安装检测，直接下载不能冒充原生源已验证 |
| 恢复凭据 / Ledger / 证书存档 | 对应密钥、接收证书及授权；真机分别证明 BitLocker/FileVault/Recovery Lock 等选定恢复动作；Ledger 使用原安装密钥核验历史；存档不能替代 APNs/Profile 运行材料 |
| SMTP / Webhook | 经批准 profile/目标及真实对端凭据；核对 TLS、权限、实际投递/签名确认、失败和未知结果；不将资格消息接受视为收件箱或业务处理完成 |

### 每轮记录与结论

在源码仓外的受控验收目录保存 run-id、UTC 开始/结束时间、输入摘要、范围及设备矩阵。每项记录需求/场景、required/excluded 及理由、预期/实际、结果、操作者、tenant/device/registration、原 operation/request ID 和脱敏证据路径。初始结果为 not_run；执行后区分 passed、failed、blocked、unknown，未知或缺依赖不能填成 passed。

保存产品审计关联、设备侧观测、必要截图和真实制品摘要；不收集密码、Cookie/token、私钥或恢复秘密。ACK、APNs 200、上传成功和健康探针只证明各自阶段。失败保留原操作与诊断，修复后开新轮次，不清库、换 CA 或重新注册来覆盖旧失败。

只有本轮必选项均有实际证据且通过，才能声明确切候选、OS/架构、注册方式、能力和拓扑范围内的结论；共享 CA、同机全部组件和各设备组合分别限定。未选能力、未测组合、HA/容量/性能、异址恢复及未来跨版本升级均不能从该结果推导为支持；升级边界见[版本切换](operations.md#版本切换)。
