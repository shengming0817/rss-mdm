# 身份与产品授权

MDM 嵌入 rss-identity 公共组件，由 Identity 持有账户、认证与会话，MDM 持有资源权限。Identity 管理员不会自动获得设备或业务管理权。首次安装及管理员恢复见 [安装指南](../deployment/installation.md)。

## 登录与企业身份

浏览器通过同源网关访问 rss-web 与产品 API。真实 TCP peer 必须匹配可信网关后才接受覆盖后的来源地址；cookie、Origin、CSRF 保护不可由前端隐藏按钮替代。每次请求在线验证会话，存储故障拒绝授权，被动 GET 不延长 idle。

配置入口为 [示例配置](../../fixtures/mdm-config.example.json)。不启用 OIDC 时本地认证独立可用；启用时使用产品域名的 `/api/v2/oidc/callback`，精确匹配注册回调。外部主体按 issuer/subject 显式关联，不按邮箱自动绑定。IdP 不可用不阻断本地认证。账户停用、会话注销和来源禁用必须及时阻断后续访问。

私有 IdP 需显式批准 tenant、issuer、client 和全部解析地址，仍验证 TLS；网络准入不代表 MFA 或业务授权。私钥与 client secret 由受保护部署配置持有。敏感账户/IdP 操作要求近期认证；恢复密码使用 maintenance 凭据，不能把它挂入运行服务。

## 权限计算与维护

授权主体可为精确用户、可信 IdP 组/部门（精确或子树）、显式本地用户组。标签与邮箱不构成权威；来源过期或配置身份变化不能沿用旧证明。操作与 scope 必须在同一 grant 内匹配，再合并有效 grant，默认拒绝。管理对象一般使用 tenant 范围，设备操作使用设备范围；声明权限不代表未实现动作已可执行。

每请求读取一致的规则/成员快照，不跨请求缓存。异步执行、注册续接和最终绑定重新核对当前授权。规则与成员写入在实例/租户事务内串行化并重验权限，成员维护还要求授权管理权，不能成为隐式委派。

通过 `/api/v1/authorization` 读取当前权限，通过对应 rules、user-groups、departments 入口维护规则与主体。写入携带稳定 operationId 与 expectedRevision；删除保留墓碑，UUID 不复用。提交未知按原身份精确重放；历史回执不会恢复已删除权限。分页版本变化时重新读取，禁止混合成员快照。

`initialize-authorization` 仅显式执行一次，核对真实 Identity 主体后初始化管理规则。`serve` 不补种子；删除末位管理员权限后不能靠重启或重放初始化恢复。部署恢复须由受控运维流程处理。

旧中央身份、会话与新实例不自动映射；历史审计保留原含义。授权设计原因见 [持久授权 ADR](../architecture/adr/202609200002-2363-persistent-authorization.md)，HTTP 形态由 [应用源码](../../crates/app/src) 持有。
