# #2363 持久化主体规则与请求授权

状态：已决定并实施；替代 #2343/#2347/#2348/#2390 的静态 MDM binding/角色权限设计。Identity 账户/provider 管理策略独立保留。安装仅支持全新数据库，无旧格式转换。

## 决定

MDM 拥有四类主体：精确 instance/tenant/principal 用户、带 provider/issuer/configurationVersion 的稳定 IdP 安全组、同来源的部门 exact/subtree、本地显式用户成员组。规则直接保存 operation+scope 配对，无角色模板、隐式继承、嵌套组或动态成员框架。

Identity #2451 拥有完整组织快照与签名/会话/存储校验。MDM 只消费借用的有效事实 wrapper，不从 claim 自报坐标或 displayName 推导主体。每项来源事实有独立截止时间，每次权限使用检查，来源过期仅移除依赖该来源的 grant；证明过期拒绝整个请求。旧会话保存自身快照，不查询「最新目录」替代签名观察。

请求获得权威身份后，单 SQL 读取当前规则和成员的一致快照；进程没有授权缓存。Windows 每次续接/最终绑定、延迟发布执行前重读，事务等待后重新检查来源与证明期限。操作/范围按同一 grant 匹配，随后取并集，默认拒绝。所有业务和授权管理使用此路径，Identity 管理保留其宿主独立策略。

授权写入复用 AccessStore 的角色/RLS、事务、operation receipt 和审计。每实例/租户 advisory lock 串行化 CAS/容量判断，锁后重读当前授权；本地组写入同时要求授权管理权，成员变更不能成为隐式授权委派；唯一操作身份检测重复载荷，永久 tombstone 禁止复用，重放只返回历史结果。新库由显式 initialize-authorization 先通过当前安装的 Identity 本地认证核对主体，再原子写入持久标记与首条管理规则；serve 永不种子。保留有界文档和分页，避免每请求快照无界增长。

## 取舍与影响

静态配置无法满足成员移除及时生效，角色与独立设备白名单容易形成隐式授权；均删除。通用 ABAC 表达式、角色嵌套与策略引擎增加规则解释和重放语义，本期四类主体无需这些机制。单请求快照提供一致决策；提交后新请求读取新授权，在途快照仅继续到自身证明/来源期限，关键续接主动重读。

操作契约、边界及验证入口见 [授权指南](../../guides/202609200002-2363-authorization.md)。部门 producer 仅支持能提供可信完整快照的 IdP；真实 Keycloak 使用 admin-only JSON 属性和内建映射器，无自写 Java。AAD/一般 OIDC 身份与安全组能力不等于已有可信部门目录。

## 上游源码依据

- [Kubernetes v1.35.0 rbac.go](https://github.com/kubernetes/kubernetes/blob/v1.35.0/plugin/pkg/auth/authorizer/rbac/rbac.go)：阅读 RulesAllow/RuleAllows，将操作与资源限制在同一规则内求值；未复制角色或聚合框架。
- [SQLx v0.9.0 transaction.rs](https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-core/src/transaction.rs)：阅读 commit/rollback/Drop，沿用现有 AccessStore 事务与失败回滚，不建立第二套审计/事务机制。
