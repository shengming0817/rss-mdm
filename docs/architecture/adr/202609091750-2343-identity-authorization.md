# 内嵌权威认证与 MDM 请求授权

静态 MDM 角色、binding 与 allow_* 授权部分已由 [#2363](202609200002-2363-persistent-authorization.md) 替代；下文相关段落保留为历史决策。
状态：已决定；#2437 修订并替代 #2343 的中央认证和产品会话设计。对应 PRD §06.13；验证以产品 PR 的受测 HEAD 为准，不代表生产 T3。

MDM 直接消费 Identity 的 core/postgres/http-axum/oidc 四个公开包，使用同一完整 Git revision。组件拥有本地账户、凭据、权威会话、账户管理与可选 OIDC 联合；MDM 拥有实例、租户、数据库角色、秘密、生命周期、管理策略和资源授权。原生组件 Router 直接挂载，OIDC callback 为产品 `/api/v2/oidc/callback`。未配置 OIDC 时，本地启动、登录、刷新及退出只需 MDM 自有 PostgreSQL。

每个受保护业务请求从组件权威验证获得 `AuthenticatedSession`，再形成唯一私有请求级 `Principal`；主体坐标固定为 `(instance, tenant, principal)`。不缓存认证成功证明、不接受浏览器构造身份、不提供 SessionId 二次认证入口。Policy 检查证明仍有效、实例/租户一致，再检查角色、设备范围及显式许可。HTTP 请求统一使用组件 `authenticate_request`，严格 cookie、同源、CSRF 与 active/passive 语义由组件持有；被动查询不延长 idle。

组件持有自身原子安全事件和事务预算，宿主不能通过全请求 timeout 或另一层产品审计覆盖已结算的原生响应。产品业务变更与成功审计仍在产品事务中提交；查询/拒绝审计失败不放行产品数据。产品数据库池、组件 runtime/KDF 均由生命周期作用域即时接管并有界关闭。

账户/IdP 管理由窄 `ManagementPolicy` 控制：同实例、同租户、accounts/providers 显式许可；自助改密仅本人；读取列表外的管理操作要求 Recent(300s)。配置中的账户管理员不得经 HTTP 停用或移除成员关系，变更管理员集合需部署配置调整。五种产品角色可读显式设备范围；wipe 保持管理员角色加显式许可的原义，不增加 MFA 承诺。发布管理及人员分离按原产品权限执行。

Windows 注册仅保留容量 10000、最长 300 秒、不续期、可零化的组件凭据引用缓存。后续请求查到凭据后，每次重新权威验证并检查当前设备权限；撤销、注销、轮换、停用或 PG 不可用均阻断。缓存不签发会话、不存成功证明。

全新 PostgreSQL 17 实例安装完整 RSS schema 与 Identity v9；安装绑定实例、存储 lineage/epoch 和租户，并核验实际 runtime/maintenance 角色。已提交产品 SQL 不变，追加迁移表达字段和权限调整；旧或不完整账本、摘要、安装坐标不匹配时拒绝并保留数据。`migrate`、`initialize`、`recover-password` 为独立 operator 路径，日常账户操作不使用 maintenance。

不读取旧 cookie，不保留中央协议、远程 validate、MDM 独立浏览器会话、旧配置、候选 fixture 或回退开关。旧主体坐标与新实例坐标不自动对应；外部 subject 保持不透明，不按邮箱自动关联。旧审计保留历史含义，旧会话和非终态业务不续接。回退仅指停止新部署后恢复旧独立部署及其一致备份。

HTTPS 网关按真实 peer 限流并覆盖来源头；后端只在实际 TCP peer 匹配 trusted_gateway 后读取单一转发地址，浏览器监听保持 loopback。构建及实际候选使用 Docker 默认平台，平台身份取实际 OCI 元数据。配置和操作见[认证指南](../../guides/202609091600-2343-mdm-identity.md)与[候选部署](../../deployment/202609120000-2353-candidate-deployment.md)。

组件 pin 和 lock 为依赖真源；普通及测试闭包必须分别验证唯一来源/revision，不能通过跨仓 path/patch 消除类型边界。#2365 对最终 RSA 公钥验签路径要求独立限定接受，旧接受不继承；#2364 持有部署浏览器验收。真实 PG、Keycloak 与 MDM OCI T2 不替代生产或设备 T3。
