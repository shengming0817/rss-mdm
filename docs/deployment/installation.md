# 候选构建与安装

## 构建 V3 候选

构建使用当前工作区源码，包含未提交修改、新增非忽略文件及删除；源码路径由 workspace 成员与构建输入限定。Git revision 与 dirty 仅作记录，不作为运行准入证明。构建机需要 Docker Buildx、私有 Git 只读凭据和不可变 rss-web image ID/repository digest。

```sh
python3 hack/release.py --output artifacts/candidate --git-auth-header-file /private/azure-header --web-image "$MDM_UI_IMAGE_ID"
python3 hack/candidate_smoke.py --candidate artifacts/candidate
```

授权头文件须为 owner 独占普通文件，只以 BuildKit secret 供依赖获取使用。构建从一次源码副本生成正式 OCI，复用正常缓存；失败不发布候选目录，已有输出不覆盖。

V3 候选包含 server.oci.tar、identity-ui.image.tar、candidate.json、示例配置、deployment 下的角色 SQL 与 nginx 配置，以及普通构建记录。manifest 固定实际镜像身份、归档摘要、平台、依赖提供者及全部部署输入摘要。恢复时先核验归档与部署输入，再 docker load；不从 tag 拉取替代品。V2 必须重新构建，没有兼容解析或转换器。

安装、smoke 与认证验收不要求 matching checkout、Git 元数据或 clean HEAD。把运行工具与候选放到独立目录也可执行，工具从候选目录读取角色和网关文件。候选摘要保护所交付内容的一致性，不替代分发渠道信任。

smoke 启动实际 OCI、自有 TLS PostgreSQL 与 HTTPS 网关，验证迁移、初始化、权限、重放、健康与关闭；不构建第二个消费者。成功与资源清理完成后才发布 smoke.json/smoke.log，失败移除旧成功标记并保存脱敏诊断。真机 T3 另行提供。

## 全新实例安装

使用 candidate.json 固定的依赖和二进制 --describe 声明的安装单元。仅接受安装器明确支持的基线；升级前置与失败恢复见 [运维](operations.md)。

由数据库管理员创建专用数据库和 `mdm_owner`、`mdm_runtime`、`mdm_api`、`mdm_access` 基础角色。所有产品角色均禁止 SUPERUSER、BYPASSRLS 和高权继承；`mdm_owner` 需要该数据库与 public schema 的 CREATE 权限，但不持有 CREATEROLE。`mdm_api` 是组件 reader 的验证角色，不进入 serve 配置。

再按顺序安装候选目录 deployment/ 中的 `software-publication-roles.sql`、`management-roles.sql`、`identity-roles.sql`、`commands-roles.sql`。脚本创建的 NOLOGIN profile 保持为权限角色；仅对实际配置的连接角色启用 LOGIN 并设置独立秘密，不额外授予继承权限。Identity runtime/maintenance 不继承 owner；owner 的准入检查所需切换关系由随附 SQL 设置。

`migrate` 使用 mdm_owner；`initialize` / `recover-password` 使用 mdm_identity_maintenance；`initialize-authorization` 使用 mdm_access 显式初始化一次产品授权；`serve` 只使用对应运行角色。安装会检查实际 runtime/maintenance 权限，脚本成功不代表角色准入成功。

迁移输入含 database 和 installation；installation 固定 instance_id、target、lineage、epoch 和所有租户。初始化输入另含 tenant_id、principal_id、login、password_file；通过组件维护接口初始化，日常账户与 IdP 管理使用受保护公共 HTTP 接口。

~~~sh
docker load --input server.oci.tar
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE migrate --config /run/mdm/migrate.json
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE initialize --config /run/mdm/initialize.json
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE initialize-authorization --config /run/mdm/authorization.json
docker run --name rss-mdm --network host --mount type=bind,src=/private/mdm-runtime,dst=/run/mdm,readonly IMAGE serve --config /run/mdm/config.json
~~~

IMAGE 替换为 candidate.json 固定镜像身份。秘密和配置文件由 UID 10001 持有且权限 0600。安装目录与运行目录分开准备；镜像不嵌入配置或私钥。

## 管理员密码恢复

准备独立 recover.json，沿用初始化配置的 installation、tenant_id 与既有 principal_id；`login` 必须为 null，`password_file` 指向新密码文件，database 使用 mdm_identity_maintenance。该操作轮换密码并撤销旧会话，不创建主体，也不恢复 MDM 业务授权。

```sh
docker run --rm --network host --mount type=bind,src=/private/mdm-operator,dst=/run/mdm,readonly IMAGE recover-password --config /run/mdm/recover.json
```

配置与秘密为 owner 独占的普通 0600 文件，末级路径不得为符号链接；CA 为可读 PEM。maintenance 密码与恢复文件仅挂入 operator 容器，不挂入运行服务。恢复后验证新登录并按受控秘密管理流程处置临时密码文件。

## 运行配置与网络

运行配置从交付的 mdm-config.example.json 填写：实例、租户、产品域名、数据库地址、独立秘密、Windows CA/协议密钥和 TLS 输入。各数据库角色连接同一 MDM 数据库。OIDC 可不配置，本地认证无需参考应用或企业 IdP；企业接入使用产品自己的 `/api/v2/oidc/callback`。账户坐标及旧、新主体不自动对应的边界见认证指南。

Linux host 网络使回环浏览器监听与同机 HTTPS 网关配合；Windows 协议由产品直接终止 TLS/mTLS。采用 `deployment/nginx.conf`，替换产品域名和证书路径；覆盖 X-Forwarded-For 为真实 peer，清空 Forwarded，限制真实 peer 的登录频率、连接数、正文与读取时间。后端只在真实 TCP peer 匹配 trusted_gateway 后采用覆盖后的单一来源地址。不能把浏览器监听直接暴露或接到未受控转发器。
