# 身份与产品授权

MDM 嵌入 rss-identity 公共组件，由 Identity 持有账户、认证与会话，MDM 持有资源权限。Identity 管理员不会自动获得设备或业务管理权。首次安装及管理员恢复见 [安装指南](../deployment/installation.md)。

## 登录与企业身份

浏览器通过同源网关访问 rss-web 与产品 API。真实 TCP peer 必须匹配可信网关后才接受覆盖后的来源地址；cookie、Origin、CSRF 保护不可由前端隐藏按钮替代。每次请求在线验证会话，存储故障拒绝授权，被动 GET 不延长 idle。

配置入口为 [示例配置](../../fixtures/mdm-config.example.json)。不启用 OIDC 时本地认证独立可用；启用时使用产品域名的 `/api/v1/identity/oidc/callback`，精确匹配注册回调。外部主体按 issuer/subject 显式关联，不按邮箱自动绑定。IdP 不可用不阻断本地认证。账户停用、会话注销和来源禁用必须及时阻断后续访问。

私有 IdP 需显式批准 tenant、issuer、client 和全部解析地址，仍验证 TLS；网络准入不代表 MFA 或业务授权。私钥与 client secret 由受保护部署配置持有。敏感账户/IdP 操作要求近期认证；恢复密码使用 maintenance 凭据，不能把它挂入运行服务。

密码失败防护由 Identity 统一持有：账号在首次失败起算的固定 10 分钟窗口内允许 5 次失败，成功密码认证清零，拒绝不延长窗口。Cookie、Bearer、密码重认证及本人改密共享此策略；正确密码重复认证不累计账号失败次数。来源资源预算仍独立约束所有准入认证请求，不因成功退款。429 的 `Retry-After` 表示按当前已生效限制计算的最早重试秒数；不要立即重试或自动重放写请求。来源预算、KDF 并发及固定配置边界见所固定 [Identity 的密码防护契约](https://dev.azure.com/shengming0923/rss/_git/rss-identity?path=/docs/guides/embedding.md&version=GC752718ac87ad94661506633f49459a9f65a8261f)。

失败窗口跨来源共享，恶意失败可能暂时阻止正确密码登录；已有合法会话不因此撤销。保留可用管理会话，必要时按安装指南执行受控密码恢复，不以重启或直接删数据库计数作为恢复方式。本次依赖使用当前全新安装 schema，不提供旧生产库升级路径。Identity 审计投影复用产品原生保护 keyring 加密恢复材料；恢复数据库时必须同时保留对应的原生历史密钥，不能因普通业务材料已重加密就移除仍用于审计恢复的密钥。

## 程序化访问

无人值守后台任务优先使用专用租户 API Key，仅授予任务需要的操作及资源范围，并设置到期和轮转计划；不要逐次使用管理员密码建立会话。账户 Bearer 适用于明确需要自然人账户上下文的短期程序化操作，按既有期限复用；它通过密码签发，仍受密码防护限制。程序化调用通过 HTTPS 访问同一业务 API。安装管理用户先通过浏览器 Cookie/CSRF 调用 `GET/PUT /api/v1/tenant-administration/api-access/network-policy`，配置允许的来源 IP/CIDR；写入携带 `operationId`、`expectedRevision` 和 `networks`。初始空列表拒绝所有程序化访问，包括 Bearer 登录；它不阻断浏览器管理入口。策略持久化并在下一请求重新读取，不需重启。IPv4 和 IPv6 均支持，单个 IP 仅允许该主机。来源只采用已验证的真实 TCP peer／可信网关链，不接受调用者任意指定的转发头。

账户通过 `POST /api/v1/identity/tenants/{tenant}/bearer/login` 提交本地 `login/password`，取得 `accessToken` 后使用 `Authorization: Bearer ...`。Token 由 Identity 签发并持有，延用账户当前权限；账户停用、会话撤销后失效。空闲期限为 15 分钟、绝对期限为 4 小时，成功认证请求（包括 GET）刷新空闲期限，不延长绝对期限；没有 refresh token，过期重新登录。`POST .../bearer/logout` 撤销当前 Token，账户的全部会话撤销同时覆盖 Cookie 与 Bearer。

API Key 属于业务租户，由具有 `authorization_read/write` 的租户账户管理。创建者仅为审计信息，创建者停用或退出不撤销 Key。`/api/v1/api-keys` 提供列表和创建，`/{id}` 提供详情和更新，`/{id}/rotate`、`/{id}/revoke` 用于轮换和永久撤销。创建时客户端预先生成 `id` 和 `operationId`；修改带 `expectedRevision`。名称、启用状态、可选到期时间和显式 grants 由管理者维护，字段以 [HTTP 定义](../../crates/management-http/src/api_access.rs) 和 [权限模型](../../crates/authorization-service/src/model.rs) 为准。

每租户累计最多保留 1000 个 Key ID，元数据及创建者信息总计最多 2 MiB。撤销保留 ID 和审计历史，不释放额度；轮换沿用 ID，不增加 Key 数量。

Key 通过 `X-API-Key` 传递；完整随机密钥仅在创建或轮换成功的首次响应返回，服务端只存摘要。幂等重放仅返回回执，不能找回密钥。提交未知时，用原操作查询／重放确认，再以新操作轮换；不要假设失败响应表示没有创建。丢失密钥同样通过轮换恢复，怀疑泄露则撤销或轮换。Key 支持显式授权的设备、资产、策略、软件、内容、任务和受管注册业务；不提供个人自助、身份账户/IdP 管理、授权规则/成员管理或安装租户管理权。这些管理能力当前没有对应机器凭据入口，须由获授权用户在已有会话中操作，不能通过增加 Key grants 或后台反复登录管理员账号绕过限制。轮转应在到期前完成：安全保存新密钥并切换任务，轮转后旧密钥立即失效；没有 refresh token 或自动续期接口，到期后由授权管理者显式轮转并维护到期设置。

每次请求只接受一种凭据，混用 Cookie、Bearer 或 Key、重复认证头均拒绝，不回退到其它凭据。Key 与账户在审计中具有独立主体身份。异步任务保留操作授权依据：重命名或轮换不取消已授权任务；禁用、撤销、修改 grants 或到期设置使旧授权失效，重新启用不会恢复旧任务。上传、注册续接等进行中的请求仍重验原凭据，旧 Key 轮换后不能继续绑定。

## 权限计算与维护

授权主体可为精确用户、可信 IdP 组/部门（精确或子树）、显式本地用户组。标签与邮箱不构成权威；来源过期或配置身份变化不能沿用旧证明。操作与 scope 必须在同一 grant 内匹配，再合并有效 grant，默认拒绝。管理对象一般使用 tenant 范围，设备操作使用设备范围；声明权限不代表未实现动作已可执行。

每请求读取一致的规则/成员快照，不跨请求缓存。异步执行、注册续接和最终绑定重新核对当前授权。规则与成员写入在实例/租户事务内串行化并重验权限，成员维护还要求授权管理权，不能成为隐式委派。

通过 `/api/v1/authorization` 读取当前权限，通过对应 rules、user-groups、departments 入口维护规则与主体。写入携带稳定 operationId 与 expectedRevision；删除保留墓碑，UUID 不复用。提交未知按原身份精确重放；历史回执不会恢复已删除权限。分页版本变化时重新读取，禁止混合成员快照。

`initialize-authorization` 仅显式执行一次，核对真实 Identity 主体后初始化管理规则。`serve` 不补种子；删除前必须先交接另一条有效管理员授权。当前没有内建的授权恢复或重新种子入口，重启、重放初始化和密码恢复都不能恢复已删除的 MDM grant。

旧中央身份、会话与新实例不自动映射；历史审计保留原含义。授权设计原因见 [持久授权 ADR](../architecture/adr/202609200002-2363-persistent-authorization.md)，HTTP 形态由 [管理 HTTP](../../crates/management-http/src) 持有。

## 安装管理租户

安装拥有一个默认生成的保留管理租户，账户仍需显式初始化。管理租户与业务租户复用 Identity 的账户、认证、会话和 MDM 规则存储；只有管理租户用户能够获得租户管理资格。业务 grant、IdP 组、部门、本地用户组均不能跨越这一边界。

管理租户规则入口为 `/api/v1/tenant-administration/authorization`、其 `/rules` 与 `/rules/{id}`，请求、分页、CAS、幂等回执和审计沿用既有协议。规则仅支持本租户直接用户与 tenant scope，允许 `tenant_create`、`tenant_read`、`tenant_update`、`tenant_delete`、`tenant_administrator_create`、`identity_accounts_manage` 及 `authorization_read/write` 独立权限。`tenant_read` 覆盖详情、列表及操作回执读取。租户 CRUD 和为业务租户创建管理员的 HTTP 入口、幂等与 CAS 要求见[安装指南](../deployment/installation.md)。

初始管理用户始终保留账户管理与授权读写；可以给其它管理用户委派其中任意权限。账户维护由持久化的 `identity_accounts_manage` 授权控制，普通新增账户不自动获得产品权限；租户管理员创建入口则原子创建账户和完整业务管理员授权。管理用户不能进入任何业务接口，业务用户不能进入管理规则接口；管理租户不接纳联合身份或 provider 管理。每个产品 origin 复用一个 `__Host-identity-session` cookie，切换租户登录会切换当前会话。

## 业务配置权限

`registration_configuration_read/write`（tenant scope）分别控制 Apple 组织/ADE、Windows Entra 注册策略及注册配额/准入配置的读写；`audit_read` 控制审计检索。这些业务权限可显式授予账户或 API Key，不能借此管理授权规则。业务管理员初始化包含这些权限；已有自定义规则需按业务需要重新配置，不将 `authorization_read/write` 兼容映射为新权限。Apple 的管理控制面使用共同管理认证与来源策略；原生注册、账户自助桥接和设备协议仍使用各自认证 owner。

## 管理审计检索

`GET /api/v1/audit-events` 与设备时间线使用 `audit_read` 权限及正常请求上下文。支持按设备、operation、主体、动作、结果和记录时间检索；租户/实例来自可信会话，客户端不能覆盖。响应仅包含安全事实投影，不返回凭据、原始 payload、任意 details 或执行输出。普通审计读取不表示已完成密码学账本验证。
## 运行诊断

运行诊断通过 `GET /api/v1/runtime/diagnostics` 查询；使用现有授权规则，为获准运维主体显式授予
`{"operation":"runtime_diagnostics_read","scope":{"kind":"tenant"}}`。设备范围无效，既有管理权限不隐式包含此权限。
撤回规则后后续请求重新加载授权并拒绝查询；查询绑定当前宿主实例和租户。
诊断语义与认证或审计依赖失败时的处理见[运维与恢复](../deployment/operations.md)。

资源审计查询 `/api/v1/audit-events` 支持 `targetId/targetType` 精确组合筛选，目标响应为 `{type,id}`。
时间范围继续使用录入时间 recordedAt 的 `[from,until)`，observedAt 独立保留。
游标绑定筛选、主体和有效授权依据；变更条件或权限后从首页开始，不接受旧游标。源事实中已有的 mdm 类型保持原值，不根据当前资源补猜历史类型。


## 登录资料与业务字段

资料由 Identity 保存，MDM 只持有字段定义并在读取时投影，不复制属性值。本人 `GET /api/v1/user-profiles/me`
读取本次登录绑定的观察；同一来源后续登录替换观察后，旧会话仍可有效，但资料返回 unavailable。
`?view=latest` 显式读取本人最近观察；`/api/v1/user-profiles/{principalId}` 使用 latest 语义并要求
`user_profiles_read`。latest 按目标账户实际观察分页发现来源，不依赖查看者登录来源或先建立业务字段映射。API Key 不提供自然人资料上下文。固定资料、映射字段、来源、观察期限和完整性由这一个产品响应组合。
必填只表示资料完整性，不阻止基础登录。过期或无效资料不沿用旧值，refresh 和 GET 不更新采集时间。

设置中的用户字段入口由 `user_attribute_definitions_read/write` 独立控制；写定义不授予样本读取、账户管理或本地资料写入。
定义及批准来源元数据通过 `GET /api/v1/user-attribute-definitions` 读取，分页继续使用响应 `nextCursor` 作为 `after`。
详情与写入位于 `/{fieldId}`；PUT 携带 `operationId/expectedRevision/value`，value 为 null 表示删除。
最多同时启用 128 个字段。来源、路径或类型约束变化默认等待下一次登录；明确选择使用已有观察仅重投影仍有效的观察，不延长其期限。
纯展示修改保留采集门槛，停用和删除立即停止暴露。字段使用严格 JSON Pointer，不执行表达式、脚本或远程取值。

普通字段配置可见范围为 self、profiles_read 或 both；敏感预览始终脱敏。`preview=true` 读取还要求
`user_profiles_read`，定义写权限不能隐含读取样本。本地资料由共享账户管理入口维护，受独立账户管理策略、CAS 和回执约束，
修改只更新本地来源，重新登录才产生新观察。

收到 409 后重新读取定义；提交结果未知或响应丢失时，以原 operationId 查询
`GET /api/v1/user-attribute-operations/{operationId}`，不要自动重放写入。操作回执绑定租户、实例和调用主体，当前权限仍须有效。
会话的 issuedAt 只表示签发时间；Apple/WNS/存储/邮件/任务签名/Webhook 和设置的近期认证判断均使用真实认证时间，未知、未来或过旧时拒绝。

MDM 不暴露 Identity 的原始 `/api/v1/identity/tenants/{tenant}/profile` 观察读取；本人及他人资料统一经过 MDM 字段投影。本地资料管理仍使用受账户管理策略保护的 accounts 路径。`profiles[]` 的 `providerConfigVersion/sourceRevision` 是该观察接受时的来源版本（不适用为 null），不会替换为读取时的最新版本。
