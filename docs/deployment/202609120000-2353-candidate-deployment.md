# MDM 候选构建与部署

候选为 rss-mdm 单一生产可执行文件，镜像运行用户 10001:10001。构建、加载、运行和 smoke 使用当前 Docker 默认平台，不提供项目级平台参数。candidate.json 从实际 OCI config 记录 OS、architecture 和可用 variant，绑定源码 SHA、Cargo.lock、组件来源、安装单元、二进制和归档摘要；输入镜像使用多架构索引摘要。设备和软件包的业务架构字段不受影响。

## 构建与验证

在干净、已提交源码执行，构建机需 Docker Buildx 和私有 Git 只读凭据。授权头文件须为 owner 独占普通文件，仅作为 BuildKit secret 提供给 cargo fetch，离线编译和运行镜像不保存凭据。

~~~sh
python3 hack/release.py --output artifacts/candidate --git-auth-header-file /private/azure-header
python3 hack/candidate_smoke.py --candidate artifacts/candidate
~~~

输入镜像由 `deployment/providers.lock.json` 固定。Rust 使用容器原生工具链和标准 `target/release` 路径；MDM 专属 Cargo 缓存用 BuildKit 自动 TARGETPLATFORM 隔离。候选目录只在所有构建检查通过后发布，失败可原命令重试，已有目录不覆盖。

smoke 只运行实际 MDM OCI、自有 TLS PostgreSQL 和 HTTPS 网关。它执行安装及重放、初始化、本地登录、实例/租户/主体检查、设备注册及幂等重放、设备范围与 wipe 拒绝、拒绝无业务效果及审计、刷新轮换、退出、健康及有界关闭。runtime 和 operator 使用分离的秘密卷；服务不挂载安装或 maintenance 密码。测试网络命名空间只为本地候选运行，不证明生产拓扑。

全部检查和资源清理完成后才原子发布 smoke.json 及其绑定的 smoke.log。失败重跑移除旧成功标记；清理前保存独立 smoke-failure.json，包含产品/网关安全日志与容器状态，不采集可能含输入值的 PG statement 日志。交付目录含 server.oci.tar、candidate.json、smoke.json、smoke.log、evidence 和示例配置；使用前核对摘要。此验证不含 Windows/macOS 真机 T3，也不代表生产发布。

## 全新实例安装

当前版本要求全新 PostgreSQL 17 实例，完整 RSS schema 和 Identity v9。旧 ledger、摘要、安装主体或存储坐标不匹配时拒绝；不回填旧 Outbox、不改历史 digest、不删数据重试。旧账户、会话及非终态业务不续接。

按[认证指南](../guides/202609091600-2343-mdm-identity.md)准备数据库基础角色，再按顺序安装候选源码中的 `software-publication-roles.sql`、`management-roles.sql`、`identity-roles.sql`（位于 `crates/app/schema/`）。为各运行角色配置独立登录秘密。`migrate` 使用 mdm_owner；`initialize` / `recover-password` 使用 mdm_identity_maintenance；`serve` 只使用对应运行角色。安装会检查实际 runtime/maintenance 权限，脚本成功不代表角色准入成功。

迁移输入含 database 和 installation；installation 固定 instance_id、target、lineage、epoch 和所有租户。初始化输入另含 tenant_id、principal_id、login、password_file；通过组件维护接口初始化，日常账户与 IdP 管理使用受保护公共 HTTP 接口。

~~~sh
docker load --input server.oci.tar
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE migrate --config /run/mdm/migrate.json
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE initialize --config /run/mdm/initialize.json
docker run --name rss-mdm --network host --mount type=bind,src=/private/mdm-runtime,dst=/run/mdm,readonly IMAGE serve --config /run/mdm/config.json
~~~

IMAGE 替换为 candidate.json 固定镜像身份。秘密和配置文件由 UID 10001 持有且权限 0600。安装目录与运行目录分开准备；镜像不嵌入配置或私钥。

运行配置从交付的 mdm-config.example.json 填写：实例、租户、产品域名、数据库地址、独立秘密、Windows CA/协议密钥和 TLS 输入。各数据库角色连接同一 MDM 数据库。OIDC 可不配置，本地认证无需参考应用或企业 IdP；企业接入使用产品自己的 `/api/v2/oidc/callback`。账户坐标及旧、新主体不自动对应的边界见认证指南。

Linux host 网络使回环浏览器监听与同机 HTTPS 网关配合；Windows 协议由产品直接终止 TLS/mTLS。采用 `deployment/nginx.conf`，替换产品域名和证书路径；覆盖 X-Forwarded-For 为真实 peer，清空 Forwarded，限制真实 peer 的登录频率、连接数、正文与读取时间。后端只在真实 TCP peer 匹配 trusted_gateway 后采用覆盖后的单一来源地址。不能把浏览器监听直接暴露或接到未受控转发器。

## 就绪、停机与恢复

/livez 表示进程可响应。/readyz 要求启动 admission、首次有界恢复与投影通过，工作任务仍运行且尚未停机；不表示 backlog 已全部追平，健康查询不额外探测 IdP。

SIGINT/SIGTERM 先停止接入并排空，再取消和 join 工作任务，最后关闭存储及认证 KDF/runtime，整体关闭预算 40 秒。关键任务异常或关闭失败返回非零；进程重启由部署 owner 决定。被动查询不延长认证 idle，组件事务使用自身预算完成，宿主不以请求 timeout 丢弃其提交结果。

监控 mdm_inventory_progress、mdm_management_retention_failure、mdm_shutdown_failure、mdm_maintenance_shutdown_failure 和 audit_failure；日志记录闭合类别与操作坐标，不打印凭据或协议正文。提交未知按原操作查询恢复，不更换幂等键或删除 ledger。

安装失败保持服务停止并保留证据。回退指停止新部署后恢复原有独立部署及其一致数据库/密钥备份；新代码没有中央认证回退路径。仅在新候选和 smoke 通过后，按精确镜像身份、归档目录和专属缓存记录清理本任务废弃产物，不进行全局 prune。
