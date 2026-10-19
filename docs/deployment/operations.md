# 运维与恢复

## 版本切换

本版本使用全新数据库安装；后续租户登记、回执恢复查询和当前安装重放见[安装指南](installation.md#全新实例安装)。安装身份、组件清单、权限或 fencing 不匹配时保留数据库及安装记录，按实际失败原因恢复。

部署使用配套数据库、服务、Agent 协议及可信签名配置。管理客户端使用 Enrollment `/api/v1`、状态型设备命令 `/api/v1`、企业脚本计划及运行 `/api/v1/script-plans`。安装前显式配置审计 Plain 或 Ledger；Ledger 的 key ID 与受保护密钥文件必须由部署方提供，缺失或错误时拒绝启动。

恢复前停止全部写入实例，按同一备份时间点恢复数据库、内容卷和原 `native_protection` 引用的全部材料，确认服务账户可读且所有实例使用同一份 32 原始字节密钥后再启动。密钥备份应存入受控秘密存储并验证可取回；不要打印密钥或提交到代码/日志。加密写钥通过 `rotate-protection` 切换，不能直接覆盖原文件；丢失原密钥后重新生成文件不能解密已有 native 数据，也不能解除比较身份校验。原生输入认证或身份完整性损坏归为永久恢复失败，记录 `mdm_command_recovery_integrity_failure` / `native_input_integrity`，不持续退避；保留证据并从一致备份恢复，不能删除 guards 后重发变更。

内容上传和清理由 PostgreSQL 控制状态协调；恢复须使用配套数据库、完整物理内容和密钥，不能仅降级二进制。卷目录中的 `.<id>.lock` 是跨实例物理发布锁，删除后保留的标记阻止迟到写者重新发布，必须随完整租户目录一起备份，不得手工删除。暂存文件由对应持久对象意图回收。

Audit、Ledger 与产品 receipts 的完整结构/权限检查只在构造和显式启动验证执行。
变更相关角色、函数或结构前，停止相关写实例并排空事务，再执行受控变更；使用 access、
flow、command、software、租户注册、管理员初始化和 Identity audit worker 各自实际连接重新验证，成功后才恢复接流。
验证失败保持停机。业务操作仍检查租户、必要隔离和持久材料一致性，并传播真实 SQL 权限失败；
不承诺逐次调用发现管理员带外配置漂移，不支持滚动混跑旧、新契约。

## 就绪、停机与恢复

/livez 表示进程可响应。/readyz 要求启动 admission、首次有界恢复与投影通过、Identity 审计首轮投递成功，工作任务仍运行且尚未停机；不表示 backlog 已全部追平，健康查询不额外探测 IdP。

经授权的 `GET /api/v1/runtime/diagnostics` 查询当前实例的组件汇总，返回 `alive`、`ready` 和 `components`。
管理员通过现有授权规则显式授予租户级 `runtime_diagnostics_read`；该权限不由设备读权限或授权管理权限隐式获得。
查询为被动会话活动，经现有请求审计结算；认证、授权库或审计不可用时仍拒绝请求，没有匿名诊断旁路。
公开健康探针只返回存活或就绪布尔值，详情和 `/readyz` 消费同一宿主聚合。

组件分别展示就绪原因、诊断 health、真实受控任务状态和适用的依赖、队列或进度。health 的 degraded/unknown 表示本次观测故障或缺失；
readiness 仍表达公开探针的既定条件，两者不能互相推断。入口暂停与依赖读取失败分开；
任务 running、已转发任务、服务就绪均不表示业务完成或设备实际效果。执行恢复只有受控任务仍运行、恢复扫描和派发首轮均确认成功且未停止时才就绪；确认空扫描/空领取也有效。
依赖扫描或派发轮次故障撤销就绪，后续成功轮次可恢复；停止信号或任一分支退出立即撤销就绪，在途事务仍按原预算结算。
未启用的 Apple 组件显示 not_applicable。

Automation 的 `bridge` 记录输入转发结果，`runner.scan` 记录独立运行连接池的实际扫描结果；
两者各自携带观测时间，转发成功不能证明 runner 健康。`runner.unresolvedAttempts` 保留本进程内
尚未由同一目标成功执行并确认结算消除的故障，`latestFailure` 只返回受控阶段、原因与时间。
扫描或其它目标成功不会清除这类故障，Retry/Suspended 结算也不算执行恢复。
最多保留 1000 个故障目标，超出后 `runner.truncated` 持续为 true，health 不能恢复为 healthy，
因为被丢弃的身份已无法核对；重启开始新的观测窗口。该窗口不替代持久任务队列状态。

队列按真实租户持久事实有界统计，`truncated` 表示计数达到源码定义的观察上限；失败时计数为 null，不能当作无积压。
Flow 的 pending/running/completed/failed/superseded 沿用既有任务状态，running 表示已转发且未终结，
不是操作系统任务存活证明；asset_changes_pending 表示尚未转发的资产输入。Inventory delivery_pending 与投影进度分别展示。
投影直接消费 RSS 的 invocation 观察和已确认位置，sourceHead 是另一时刻的 scoped journal high-water；
lagging 是位置比较，不是精确事件数或原子快照。invocationAgeMs 和 completedPassAgeMs 指明本地观察所属运行及最近完成时间，
旧进度不会被当作当前依赖健康。未读取过 checkpoint、已确认的空 checkpoint 与读取失败分别表达。

局部探测失败时查询仍可返回 HTTP 200 和已知组件结果；响应成功只表示查询成功。授权加载与诊断共用宿主绝对截止时间，
不逐依赖续期，审计由原 owner 完成结算。诊断不返回设备身份、任务输入、数据库地址、配置、秘密或底层错误原文。


SIGINT/SIGTERM 先停止接入并排空，再取消和 join 工作任务，最后关闭存储及认证 KDF/runtime，整体关闭预算 40 秒。命令 worker 停止领取后等待在途 relay 完成 gateway 事务与 outbox 结算，单任务关闭上限二十秒覆盖领取、接受、结算各六秒的预算；任一并行分支退出会取消另一分支并等待它结算。关键任务异常或关闭失败返回非零；进程重启由部署 owner 决定。被动查询不延长认证 idle，组件事务使用自身预算完成，宿主不以请求 timeout 丢弃其提交结果。

审计恢复要求各产品运行连接使用 `READ COMMITTED`；启动与每次借用事务均检查，组件不替调用方修改隔离级别。业务事务先取得 Audit head，以及 Ledger 模式下固定审计链的 head，再取得业务和 Outbox 锁。提交未知后使用原操作身份和原请求重试，锁后的新语句快照同时核对业务回执、产品审计回执与组件记录；恢复原 canonical bytes 和 recorded_at，不生成新的事件身份。单边缺失、指纹或字节冲突均拒绝并要求修复，不能补造记录。两者都不存在也只有在成功取得同一锁、确认先前数据库事务已结束后才允许重新判定业务；这不证明设备或软件源的外部副作用回滚。锁或读取超时继续保留未知状态。注册替换、撤销、Apple CheckOut 和共用退役策略的 Windows 路径保留六秒总上限，业务窗口最多四点五秒，余下四分之一留给原 Audit owner 提交/回滚；已有更早调用方 deadline 时同步收紧。截止时间在入口一次冻结，下游和逐事件追加不续期。这个兼容策略不保证任意采集积压能在六秒完成，也不是吞吐 SLO。业务超时后停止新增工作并等待原 owner 结算；上游 Acquire/Begin/Setup 尚未进入产品回调，仍受原总截止时间约束，Setup 耗尽预算仍可能回滚未确认。按实际结算状态处理，不分批伪装成完整退役。

Ledger 启动会校验既有链身份并认证有界记录窗口，同 key ID 配错密钥也拒绝启动。新空链没有历史密钥认证证据，部署方仍须保管最初配置的秘密。运行时不自动生成密钥、轮转或降级 Plain；当前部署不支持更换既有审计完整性模式。请求拒绝、查询、重放与未知结果使用独立请求事件，在受保护响应释放前完成结算。`RollbackFailed` 与 `CommitUnknown` 均不是成功回滚证明，日志也不替代持久审计。
收到 `operation_rollback_unconfirmed` 时保留原 operation 身份及原请求，按同一锁协议重试/读取原回执；
不得更换 UUID 或把暂时 404 当作回滚证明。持续不可核对时停止自动重试并由部署 owner 检查业务、
审计回执及记录的一致性，不补造记录。Agent 通道将它与 CommitUnknown 一并映射为 `operation_unknown`，
设备端使用相同 operationId 和原内容恢复，不重新执行已开始但结果未知的外部动作。

审计持久记录不一致返回 HTTP 500 `audit_integrity_error`，日志原因同名；隔离级别、权限准入或
输入契约错误返回 HTTP 500 `audit_contract_error`。这些错误需要修复数据、配置或实现，不应
按短暂依赖故障无限重试。启动诊断保留 `AuditIsolation`、`AuditAdmission`、`AuditContract` 和
`AuditIntegrity` 类别；超时仍是 `RequestDeadline`。若业务结算已未知，响应继续保留
`operation_unknown` 或 `operation_rollback_unconfirmed`，具体审计失败原因单独记入日志。

监控 mdm_inventory_progress、mdm_management_retention_failure、mdm_shutdown_failure、mdm_maintenance_shutdown_failure 和 audit_failure；日志记录闭合类别与操作坐标，不打印凭据或协议正文。提交未知按原操作查询恢复，不更换幂等键或删除 ledger。

内容故障按 `content_storage`、`content_metadata`、`content_invariant`、`content_deadline`、`content_cleanup` 和 `content_import` 区分；企业目录使用 `software_catalog_storage` / `software_catalog_invariant`，外部发布保留 `publication_storage`。`mdm_request` 的 `request_id` 关联请求，上传与续传的 `operation_id` 关联原上传会话及持久回执；这些诊断不携带文件路径、源站响应正文或凭据。

命令闭环另监控 `mdm_command_relay_failure` 与 `mdm_command_recovery_failure`：

| 条件 | 阈值与处置 |
|---|---|
| relay `transient` 或 recovery `Transient` / `Deadline` | 同一 messageId/target 持续 5 分钟告警；检查 PostgreSQL 可达性、Retry 时间和租约持有者，保持原消息与幂等键 |
| `commit_unknown` / `CommitUnknown` | 首次出现即告警；按原 operationId 查询并精确重放，不能换 ID、清 Outbox 或当作回滚 |
| `invariant` / `Invariant`、`StorageContract`、`Permanent`，尤其 `phase=runner` | 立即告警；关键 worker 退出由统一运行时关闭服务。核对候选、迁移账本、角色/ACL/RLS 与固定 catalog，修复根因后重启同一身份的服务 |

relay 的完整 messageId 保留类型前缀：`dispatch.<UUID>` 关联同 UUID 的 operation，`action.<UUID>` 关联企业任务 run；recovery 的 `target` 是设备文本 ID 的 SHA-256 scope，结合 `mdm_commands.devices` 定位。使用有设备读取权限的管理查询查看 command、最新 attempt 和 CollectionRun。`phase` 区分 claim、accept、settle 与 runner/scan；日志不携带预期值、原生正文或浏览器凭据。恢复后确认告警停止、同一 command 可继续收敛；终态任务不得因重启复活。候选契约可用 `make t2 MODULE=catalog.contract` 离线校验，生产修复是否满足契约仍由启动/事务准入判断，禁止导出漂移生产结构覆盖固定 JSON。

安装失败保持服务停止并保留证据。回退指停止新部署后恢复原有独立部署及其一致数据库/密钥备份；新代码没有中央认证回退路径。仅在新候选和 smoke 通过后，按精确镜像身份、归档目录和专属缓存记录清理本任务废弃产物，不进行全局 prune。



## Identity 审计投递

`identity-audit` 使用与 Identity 同库的独立 consumer 连接，复用产品 Plain/Ledger 模式、实例、租户和 storage lineage/epoch。每批至多两条，与 Audit 连接池容量一致；成功投递后立即继续；空闲等待通知、持久化重试/租约最近期限或三十秒恢复补扫。复用产品唯一 LISTEN 连接，监听可信实例的业务与管理租户 Identity 频道；空 payload 只作唤醒提示，不作为提交、领取或授权证明。所有订阅完成后及重连后补扫；空领取即使仍有到期候选也仅立即复查一次，随后有界等待，避免行锁竞争自旋。基础设施暂时失败保留至多一秒退避，由已知更早持久期限收紧，通知不能绕过退避。租约六十秒、发布五秒、结算一秒、安全余量一秒；关闭停止领取新批，等待当前组件调用结算，任务关闭限十五秒并受全局四十秒限制。中断不意味着回滚，重启保留原消息身份。

组件日志 `component=identity-audit` 中的 `transactional_messaging.outbox.*` 提供发布、重试和租约信息；成功 claim 的耗时 tick 不写日志，避免空轮询噪声；宿主 `mdm_identity_audit_failure.kind` 只含闭合错误类别。暂时领取故障令 readiness 为 false，后续成功轮询可恢复。若已有事件报告重试，则保持不就绪，直到实际领取并成功处理事件；退避中的空轮询不恢复就绪，初始空闲仍可就绪；就绪不等于积压清零。使用已有授权运维连接，按实际 tenant 与 `identity.security` domain 只读查看 Outbox 的 `status` 分布和对应 Inbox 回执，禁止给 worker 增加 operator 权限或导出事件 payload。

只读查询示例（psql 的 `tenant_id` 变量由已授权操作员提供）：

```sql
BEGIN READ ONLY;
SELECT set_config('rss.tenant_id', :'tenant_id', true);
SELECT status, count(*) AS events, min(retry_after) AS earliest_retry
FROM rss_transactional_messaging.outbox
WHERE tenant_id = :'tenant_id'::uuid AND domain = 'identity.security'
GROUP BY status ORDER BY status;
ROLLBACK;
```

- `transient`：检查数据库连通性和锁等待，恢复依赖后由原 worker 自动重试，或用同一配置重启；不能更换实例、租户、lineage、epoch 或消息 ID。
- `permanent`、`ownership_lost`、`invariant`：关键任务退出，服务非零关闭；核对安装版本、角色权限及 storage fencing，修复后重启同一身份。
- `rejected_event`：存在隔离事件，保持服务关闭并保存证据；启动也会拒绝既有死信。由消息 recovery owner 的受控流程处理，本产品不提供死信改表、删除 Inbox/Audit 或强制重放命令。

恢复后核对相同事件的 Audit 记录及 Ledger（启用时）一致、积压继续减少、readiness 恢复；重启不应新增重复审计。日志和源 published 状态均不代替原事务的持久结算证据。

## 接入与审计容量

配套网关对实际 TCP peer 的通用 `/api/` 请求执行每秒 10 次、burst 20 的 admission，登录仍使用
更严格的独立额度；转发头不能改写额度身份。宿主每个 HTTP envelope 最多接纳 32 个同时进行的
审计请求，健康检查及由 Identity 自有结算的路由不占此额度。超额在业务处理前返回 429
（Agent 使用既有 503 serviceUnavailable）及 Retry-After，不触发 handler 或持久审计。
已接纳请求的认证拒绝、查询及未知结果仍完整审计，不降采样、不降级 Plain，也不改变先取 Audit 锁的顺序。
Inventory 和 Windows retention 先做无行锁的只读候选检查；无过期任务时不取 Audit head。

Inventory、资产自动化、命令 relay/recovery 和原生协议维护由产品实例内唯一 PostgreSQL LISTEN 连接接收提交通知。连接只监听配置租户的独立通道，发送端从同一业务事务已绑定的租户派生通道；同租户多实例均可接收，无关租户不会被唤醒。通知仅携带闭合工作类型，不携带租户、设备或任务正文；业务事务提交后才投递，所有 worker 仍从持久状态重新读取、准入并领取。有进展立即继续，空闲等待通知或最近到期点，最长五秒补扫；既有错误退避独立保留。资产自动化成功动作后的 Reobserve 仍为二十毫秒，与五秒空闲补扫分别配置；已确认提交的短期重观察/重试可提前唤醒。初次 LISTEN 和重连完成后全部补扫，通知丢失、进程重启或多个实例均不改变持久事实的权威。`mdm_notification_connection.connected` 记录连接故障与恢复转换，SQLx自动重连完成也补记这对转换；不需要按通知数量推断完成量。

Compose 中 PostgreSQL 启动期每秒检查，稳定运行后每十秒检查。数据库健康检查不代表产品 readiness。
有候选时仍先取 Audit/可选 Ledger 锁，再锁业务行，每次至多处理 32 个会话，事务六秒、周期调用七秒有界；
超时回滚或未知时保留原状态，下轮重新读取，不能把 Audit 锁移到业务锁之后。
监控网关 429、请求延迟、审计/retention 超时与数据库存储增长；这些是部署 admission 上限，不能解释为吞吐承诺。

## 迁移失败

首次安装先持久绑定 instance、存储 target/lineage 与审计模式。每个组件的 SQL 变更和完成回执在同一数据库事务提交；进程中断或提交响应丢失后，使用原输入重试，安装器核对当前清单的精确已完成前缀并从下一单元继续。运行宿主仍只接受完整清单，不接纳部分安装。

摘要变化、缺失中间单元、重复回执、旧的不完整 intent 或安装身份不符均拒绝接续。保留数据库与原安装 journal，调查或恢复一致备份；不得改写 `mdm_migrations.complete`、删除回执、重签摘要或清空已有业务数据。当前不支持旧候选数据库升级；清单不匹配不能靠重试接入。运行角色无 DDL，启动检查 schema、权限和 RLS；修复漂移不能从生产库覆盖固定 catalog。

安装 journal 中的 Ledger 密钥是固定安装密钥。重放校验同时绑定原保护材料，缺失、损坏或替换时失败；恢复必须提供原密钥和一致备份，不切换新链、不重签历史，也不自动降级 Plain。该约束不提供同链 HMAC 换钥能力。

当前准确安装集合由二进制 `--describe` 与 [安装源码](../../crates/app/src/migration.rs) 持有。正常恢复要求数据库、候选制品、配置、内容与密钥共同匹配；清理前候选的数据库和备份不能直接接入清理后的候选。恢复旧候选时使用其匹配的原制品及一致备份，不能仅降级或替换二进制。数据库角色与首次安装见 [安装指南](installation.md)。Apple 证书、APNs 与 CA 排障见 [Apple 管理](../guides/apple-management.md)。

未来升级以真实待升级发布版本和部署需求为起点另立实施项；固定旧/新发布制品、schema、配置、数据及秘密清单，明确支持版本范围，设计停写、升级、中断恢复与备份回退，并在会改变已部署合同的版本发布前完成验证。Git 历史只提供实现参考，不自动成为受支持来源。当前没有可核验的旧部署证据，不能据此宣称已完成部署调查。

内容仓的 PostgreSQL journal 持有上传进度、对象版本、清单、额度和读 pin；服务端卷与 S3 都不能通过扫描目录或 bucket 重建业务状态。旧目录配置、上传 Saved JSON 和 checkpoint 不接受，也不自动迁移。全新安装须使用匹配 schema 和空内容 namespace；恢复旧部署时恢复匹配数据库、内容、密钥与二进制。

备份须保存数据库、`native_protection` 及清单引用的全部物理对象：卷模式保存完整租户目录，S3 模式保存确切对象版本及版本控制状态。停写后制作一致备份并联合恢复；只恢复当前 S3 key 的内容不足以恢复清单。后端身份和保护密钥标识在租户首次启用时固定，更改 endpoint/bucket/namespace/卷目录不能作为数据迁移方式。

S3 凭据由内容连接领域加密持久化；按[安装指南](installation.md)提交新材料版本，部署侧验证真实供应方身份、权限、TLS、版本化和租户前缀后，通过受控宿主重启应用确切 revision。旧版本在新候选失败时继续使用，但过期或撤销后不可用。保留历史操作与备份所需的旧材料；不能通过替换挂载文件轮换运行凭据。私有 CA 文件有界读取且不接受符号链接；不提供关闭 TLS 校验的选项。Compose 的只读 runtime 挂载用于部署输入、信任根和保护材料；S3 access/secret/session token 从持久化连接版本加载。S3 模式不使用 content 卷；卷模式继续挂载持久 content 卷。

清理先在短事务内核对业务引用与读 pin，提交“删除中”屏障后，再逐个删除确切物理版本；已删除部分持久登记，下轮继续。结果未知保留原对象意图和额度，不把未知当作不存在。不能用外部 lifecycle 规则、删除 bucket 版本或直接删除卷文件代替产品清理。原生配置保护域仍为 `content.native-configuration`，诊断使用独立保护域。


## Agent CA 与签发恢复

`agent_certificate_health` 在直接签发者状态变化时报告 healthy、renew_soon（完整签发窗口余量 30 天）、critical（余量 7 天）、issuance_unavailable（仍有效但不足一个完整叶证书窗口）、expired 或 clock_unavailable；过期及剩余期限不足均拒绝新签发。按公开 issuer 摘要核对信任锚，不在故障时另建 CA 或静默缩短叶证书期限。Agent 证书元数据包含 purpose/profile、服务端 tenant/device URI、issuer/SPKI/证书/CSR 摘要、serial 和绝对有效期。颁发输出只表示候选证书；只有实际完成的 TLS 握手可产生 peer evidence，且业务 owner 仍须逐次检查当前注册和撤销状态。

每次签发先持久提交 grant 消费和 `agent_issuances` signing 意图，审计业务身份为 `agent-enroll:agent_certificate_authorize:<operation>`；离开事务请求 CA，严格验证返回证书后保存候选并提交 `agent-enroll:agent_certificate_result:<operation>`。网络、CA、返回校验或结果审计不确定均保留同一 issuanceId，返回 issuance_unknown；status 查询不得触发二次签发。step-ca 的 `/sign` 不提供幂等回执，token 单次消耗不能证明未签发。

管理员从原 CA 持久记录找回原证书链，通过 `POST /api/v1/agent-issuances/{id}/recover` 提交稳定 operationId 与 certificateChain；服务端核对原 CSR/SPKI/SAN/签发窗口，以及签发前冻结的 issuer、provisioner/kid 和公钥摘要。恢复根据冻结的原 issuer 路由，须保留该代次的 CA/provisioner 配置；不能自动换 jti、重签或把另一 CA 的结果当作原结果。激活 ACK 丢失后使用原 activation operation 重试或查询状态，同一注册的恢复只替换凭据。日志及支持导出仅含分类和摘要，不含秘密、CSR 私钥或 JWT；step-ca 原生日志可能含 ott，必须作为受限秘密日志保存，禁止直接纳入通用日志聚合。

备份前停止 MDM 的签发调用及全部 CA 写入实例。作为同一恢复集备份 CA 数据库、root/intermediate 证书及加密私钥、CA 配置与模板、受控 CA 解密秘密、Agent provisioner 私钥/kid、MDM 配置及 Audit/Ledger 数据库；CA 配置中的绝对路径和数据库路径须按原位置恢复。秘密进入受控秘密备份，定期验证可取回。恢复时先恢复原 CA 身份与数据库，再用原 provisioner 私钥和匹配的 MDM 审计数据启动；核对 issuer/SPKI/kid 摘要、已有 serial 和 token 使用记录，并在隔离环境签发新授权、校验证书链及双阶段审计。不得删除 CA token 表、重置 Audit head、重新生成 CA 或用新密钥覆盖原文件来处理结果未知。可再生 T2 `agent.pki` 会停止 CA、备份并恢复原目录与数据库，再执行真实受控签发；生产恢复还须执行上述一致性核对。

## 设备 PKI 轮换与撤销

管理接口要求全设备 Credentials 权限，使用当前会话授权并在原 Audit 事务内复核。`GET /api/v1/pki/{purpose}/trust` 取得当前完整公开 revision；`POST /api/v1/pki/rotations` 提交 id、purpose、expected_revision 和包含一个 prepared issuer 的完整 candidate（revision+1），旧代次的公开身份与状态保持一致。先部署 prepared provider，再分发重叠信任。Windows 关联 CSP Get、Apple 关联 ManagedOnly ProfileList、Agent 认证信道的安装 ACK 形成对应设备回执；活跃登记仍缺回执时 approve/activate 返回 conflict。

`POST /api/v1/pki/{purpose}/rotations` 的 id 为原 rotation id，expected_revision 为当前 revision，action 依次为 approve、activate、retire。每个阶段保留稳定回执，未知提交沿原 id/phase 重试。每个 purpose 同时最多一个未完成轮换。激活后旧代次仅验证，新授权使用新代次；已冻结的签发/恢复沿原 CA。旧 issuer 仍有未知签发，或仍有未过期且未取得撤销发布证明的已签发证书时，不能 retire。重叠期由实际迁移/过期/撤销事实决定，不用固定等待时间绕过门禁。

Windows 未知签发通过 `POST /api/v1/pki/signing/recover` 提交原 attempt 与原 certificate chain；Agent 仅通过原 `agent-issuances/{id}/recover` 在原 owner 事务中一并恢复候选和公共签发记录。SCEP 沿原 attempt/notify 路径处理，不重新授权 consumed challenge。任何恢复均核对原 CSR/SPKI、CN/SAN、purpose、issuer、签发窗口和链，不换 CA、不换 jti、不创建替代证书。

在线撤销先在原登记/凭据 Audit 事务中立即生效，并写入实际 serial 的持久撤销队列。维护任务每 60 秒从各代次 CA 拉取 signed CRL，离开业务锁后调用 `/revoke`，失败保留 bounded backoff 任务。CA 接受 passive revoke 只表示 submitted；只有 serial 出现在经批准 issuer 签名的新鲜 CRL 中才记为 published。issuer CRL 的 nextUpdate 默认为 10 分钟，根 CRL 30 天并在到期前 7 天由离线 owner 更新；缺失、过期、号码/时间回滚或同号异内容均拒绝认证。保留连接及 TLS 恢复仍逐次检查当前凭据映射。

离线根或 legacy issuer 的 CRL 使用 `POST /api/v1/pki/crls` 发布单一 operation、purpose 和 publications 数组（1–16 项，每项 issuer、crl、root_crl，base64 DER）。同 root 的所有代次共同采用同一 root CRL，集合内冲突拒绝；不把根私钥带入在线宿主。刷新按同 purpose 完整集合校验、原子发布；停机造成多个 issuer CRL 过期后可整组恢复。备份/恢复必须保留 CA 数据库、原密钥身份、serial/token 使用记录、MDM 数据库和 Audit/Ledger；成功签发与撤销发布的未知结果仍沿原记录恢复。


设备 CA 使用 `deployment/compose.yaml` 的 `pki` profile。每个 purpose/issuer 独立 project、数据库目录和 provisioner；在线 `MDM_PKI_ROOT` 只含中间 CA 加密密钥、公开根、配置、模板及 CA 数据库，根私钥和独立解密秘密放在未挂载的离线目录。step-ca 原生 `kms` 配置选择加密文件 SoftKMS 基线，`key` 可替换为受支持 KMS/HSM URI，由 CA 部署 owner 提供对应访问凭据与验收；MDM 不读取 KMS 或根私钥。非 step-ca 企业 CA 路线登记为 #2680。

每份 CA 数据库同一时间只允许一个写入者。冷备接管先停止并移除旧 `step-ca` 容器，核对 `compose ps --all --quiet step-ca` 为空并确认旧主机被隔离，再以同一绝对存储路径和 `MDM_PKI_PUBLISH` 原端口启动独立 standby project。持久 provider origin、issuer、kid、数据库和 token 记录保持原身份；无法证明旧主隔离时不能启动新写入者。候选验证复用这份 Compose，产品 profile 暴露原生 enrollment/management/Agent 的独立 TLS 端口，网关仍只承载控制台流量。

Apple 的 challenge/notify webhook ID 和 HMAC 秘密属于稳定协议配置。新 CA 代次须沿用该 purpose 的受控 webhook 身份、回调地址和签名模板，先验证原生回调再准备/激活；不能直接采用新建 provisioner 随机产生的 webhook 身份替换已有部署配置。HTTPS、SCEP 解密、Profile 签名及 APNs 密钥仍各归原 owner。

`device_pki_attention` 每分钟输出公开 issuer 摘要、证书到期、CRL nextUpdate 与 unpublished 数量：issuer 剩余 30 天、根剩余 90 天、issuer CRL 剩余 120 秒、根 CRL 剩余 7 天或撤销尚未发布均触发。`device_pki_maintenance_failure` 按累计失败次数的幂次记录依赖故障；CA 运行或 `/revoke` 成功不代表 CRL 已发布。告警接入使用这些结构化事件并核对签名发布及原队列；密钥取回失败同时由 step-ca 的受限日志定位。所有服务实例保存历史 CRL 水位，退休后再引入同一 CA 也不能回滚已接受的号码或内容。

服务端在固定 HTTPS origin 上通过 `/api/v1/agent/enroll/trust` 匿名提供公开信任材料，该接口不授予授权；安装 ACK 仍须当前登记的真实 mTLS 与原幂等操作。首次 HTTPS 根通过受控部署渠道提供；新部署公开 JSON 也必须受保护，不能用本地测试占位材料。Agent 本机信任存储及配置更新操作由 [rss-mdm-agent 服务部署指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/local-service-lab.md&version=GBdevelop) 持有。

## 恢复凭据轮换、保留与恢复

凭据专用密钥环与 `native_protection` 分开管理。更换写入密钥时，将新旧密钥同时加入 `key_files` 并切换 `active_key`，重启后后台分批重加密，材料版本和有效性不变。移除旧密钥前确认没有剩余密文引用它；启动时校验持久密钥身份，缺失或错误密钥拒绝启用。接收证书更新独立于存储重加密：保留尚有执行或 FileVault escrow 需要的旧接收私钥，先更新端上的 escrow profile，再退出旧证书。

失效密文满 90 天后分批清除，元数据和审计保留。当前材料及未核实操作需要的材料不清除；后台同时清理已结算原生命令的秘密输入副本。失败以 `recovery_credential_maintenance_failed` 闭合诊断报告，不打印材料或密钥。数据库删除不代表历史备份已删除，备份沿用部署自己的保留策略。

停写后联合备份数据库、凭据密钥环、接收私钥及原有 native protection/内容材料。恢复使用对应密钥，重新检查当前登录授权、注册世代、撤销状态和保留期限。数据库与密钥重启/备份验证只证明服务端能按授权读取正确材料；PRK 解锁、Recovery Lock、Windows 密码登录及 BitLocker 实际恢复另由真机验收证明。


### 原生加密写钥切换

`rss-mdm-installer rotate-protection --config /absolute/private-rotation.json` 接受 `installation`（原部署输入）、`purpose`（`native` 或 `windows`）和稳定 UUID `operation_id`。专用部署进程与该操作互斥。操作先在最终保管目录生成新钥并保存每个宿主的两个不可变输入：第一阶段让全部实际进程读取新旧钥，第二阶段才切换新密文写钥。每个阶段都要求 HTTPS 返回确切宿主、操作、版本、摘要与新进程观察；失败使用原 operation ID 重试，不能手工跳过剩余宿主。

写钥切换完成后，每次调用以有界领域事务重加密 APNs/Profile/Managed Apple Account、任务签名私钥和 S3 凭据；`rewrapping` 表示还需继续用原输入调用，`complete` 表示该轮切换和上述运行材料批次已完成。私钥身份、材料版本、签名信任、ACK、原请求指纹和证书均不改变。中断可重放，单批失败回滚。

完成回执始终标记 `historicalKeysRetained=true`。历史原生输入、协议回执、物理内容块和备份仍可能引用旧加密钥，不能仅凭运行材料批次为零就删除旧钥。稳定比较钥另有持久身份用途，密文轮换不表示比较 HMAC 轮换。恢复须联合取回全部仍被记录或备份引用的材料；此流程不会自动退出旧钥，也不会修改固定安装 Ledger HMAC。


Windows 保护配置现在使用 `protocol_protection`，包含 `active_file`、`historical_files`、`fingerprint_file`。Windows 轮换先向所有启用 Windows 的宿主分发读钥，再切换写钥并分批重包注册秘密；固定 fingerprint 维持原注册/续期配置身份。旧钥继续保留供历史与备份恢复，完成写钥切换不表示旧钥可以删除。

### WNS 凭据与宿主应用

`POST /api/v1/windows/wns` 使用真实业务管理员会话、`RegistrationConfigurationWrite`、最近认证和 `Idempotency-Key`；正文是 `expectedRevision`、`packageFamilyName`、`sid`、`clientSecret`。Windows owner 加密保存候选，普通服务没有更新资格状态的数据库权限。`GET /api/v1/windows/wns` 返回当前 revision、期望版本和公开版本列表；`/api/v1/windows/wns/operations/{id}` 返回带 kind 的原操作回执。两者都不返回 SID 或秘密。`POST /api/v1/windows/wns/revoke` 接受 `expectedRevision`、`materialRevision` 和独立 `Idempotency-Key`，撤销后运行消费者拒绝该版本，旧操作可重复查询。正式 DTO 见 [WNS schema](../../crates/windows-channel/schema/Wns.json)。

部署进程调用固定 Microsoft OAuth 入口验证候选，保存资格时间及失败类别；失败至少一分钟后才重试原候选。成功后申请受控宿主重启，运行配置为 `push: {"revision": N}`，删除旧秘密文件 loader。相同 PFN/SID 的秘密轮换沿用原设备通道绑定，不要求设备因服务器秘密变化而重新注册；改变应用身份产生不同绑定，等待设备的真实 PFN/ChannelURI 查询结果。资格通过仅证明 OAuth 凭据在核验时可用，不证明离线设备收到唤醒。推送租约复核原版本仍被选择且未撤销。

设置目录 `/api/v1/settings/catalog` 和平台目录 `/api/v1/tenant-administration/settings/catalog` 使用 [SettingsCatalog schema](../../crates/management-http/schema/SettingsCatalog.json)。`configured` 只描述领域已有配置，`loaded` 只描述当前进程装载，`pending` 要求宿主应用或其他领域动作，`unknown` 明确要求 owner 观察；这些状态均不等同于真实设备验收。权限过滤先于领域读取，平台会话不会转换为业务会话。

### SMTP 固定资格投递

部署输入 `mail_profiles` 给出受限 profile ID、`hostname`、确切 `address`、`tls`（`implicit` 或 `starttls`）和 `ca_file`。普通服务只提交 profile ID，不接收任意服务器地址或 CA 管理材料。`POST /api/v1/smtp` 接受 `expectedRevision`、`profile`、`sender`、`recipient`、`username`、`password`，要求最近认证的业务管理会话、注册配置写权限与 `Idempotency-Key`。这一动作授权发送一封固定资格消息，不接收主题、正文、附件或额外收件人。

邮件 owner 加密保存凭据；部署进程对精确地址验证 TLS 名字、认证并实际投递。STARTTLS 失败不会降级，TLS 后重新 EHLO，再执行 AUTH PLAIN。DATA 发送前提交持久检查点；服务器明确拒绝与连接中断/响应丢失分别记录，未知结果不自动重投。`GET /api/v1/smtp/operations/{id}` 查询原操作，`GET /api/v1/smtp` 返回版本及选择状态。`accepted` 仅表示 SMTP DATA 取得 250 回应，不证明收件箱送达。正式 DTO 见 [Mail schema](../../crates/mail-service/schema/Mail.json)。未知操作应按原 Message-ID 从邮件系统核对，不能用新操作掩盖原结果。

实现依据 [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207)、[RFC 4954](https://www.rfc-editor.org/rfc/rfc4954) 和 [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)。不新增通知订阅产品。

### CA 准备及回调身份

`prepare-ca` 是部署操作，不是业务 HTTP 任意 CA 管理入口。输入绑定安装、租户、用途、operation_id、expected_revision、确切 CA 地址/TLS 根及管理 X509 身份。`create` 只创建固定名字和固定模板；`import` 仅接受原 kid、原私钥及完全匹配的远端用途、有效链、签名 CRL 和权限配置。原操作目录保存请求、材料及外部副作用检查点；重新执行相同输入恢复未知创建结果。已有同名但不同配置的资源拒绝覆盖。

SCEP 使用独立 RSA 解密叶证书，核对用途、签名、有效期、撤销和私钥匹配；MDM 运行宿主不读取其私钥。管理返回的两个 webhook ID/secret 分开绑定到确切 issuer 与 challenge/notify 阶段。`runtime-callbacks.json` 是受保护部署输入，不能作为公开 API 返回。`verified` 只说明 CA 身份与准备结果通过核对，`pending_channel_observation` 仍需真实 SCEP 双向回调，不表示设备注册通过。实现依据 [固定 step-ca admin client](https://github.com/smallstep/certificates/blob/v0.30.2/ca/adminClient.go) 和 [linkedca 合同](https://github.com/smallstep/linkedca/blob/v0.25.0/spec/linkedca/provisioners.proto)。

Apple 的 `identity_seed` 永久保留原 challenge/notify ID，实际凭据放在 issuer 绑定的 `webhooks` 集合。Agent bootstrap 冻结签发者，切换活跃 CA 后原请求仍沿原 CA 完成；新请求在事务内复核当前活跃 CA。未知签发不因超时或设备清理完成而解除退役门禁。

`rotate-protection` 另支持 `oidc_credentials` 和 `recovery`：复用先分发读钥、再切换写钥的宿主阶段；OIDC provider 密文由固定 Identity 依赖的原领域方法在租户事务内重加密，恢复凭据由原 recovery owner 分批重包。OIDC state 签名、恢复 RSA recipient、原凭据身份及操作摘要保持不变。旧读钥继续保留用于历史、未决操作和备份；`complete` 不能解释为可以删除历史密钥。行锁超时保留原操作重试，不把暂时锁住的密文算作迁移完成。

### OIDC 与恢复凭据宿主配置

`configure-host` 使用安装输入、稳定 `operation_id`、`host_id`、`expected_revision` 和封闭的 `change`。`{"kind":"oidc","settings":...}` 的 settings 包含 `group_facts_max_age_seconds`、`return_targets`、`assurance_profiles`、`private_providers`。首次启用在受保护的操作目录生成独立 state 签名和 provider 凭据保护材料；后续设置变更保留原密钥。提供方客户端配置仍由原 Identity 管理 API 写入。宿主入口的 `oidcEnabled` 根据实际加载配置生成，平台会话不转成业务会话。

`{"kind":"recovery","recipient":{"kind":"generate"}}` 生成独立 RSA escrow recipient 和专用保护材料；也可用 `{"kind":"import","certificate_file":"...","private_key_file":"..."}` 导入原 recipient。该证书只用于恢复材料加密，不是设备 CA。新导入检查证书、用途、有效期及私钥匹配；替换保留原 recipient 私钥，历史密文与未决设备响应继续按原身份读取。过期 active recipient 拒绝生成新恢复任务，不阻断旧密文解密。

两种变更均先持久保存候选和原操作，再重启真实宿主并核对 HTTPS 观察。开通回执记录 requested/applied revision、当前观察和失败原因；失败保留原有效宿主并沿原配置操作恢复，不能把写入配置文件当成启用成功。

`configure-host` 的 `{"kind":"ca","preparation":"<prepare-ca operation UUID>"}` 将已核验的用途 provider 和回调凭据装入现有通道，保持原 trust、原协议种子和旧凭据。之后由真实业务管理会话通过原 PKI API 发布 prepared trust、等待安装确认并激活。该部署动作不替代信任授权，不自动启用尚缺其他材料的设备通道。Agent bootstrap 在创建事务内选择数据库当前 active issuer，并从已装入的精确 issuer→SCEP 地址集合选路；重启不会把旧配置文件里的 active 标记重新当作权威。

### 当前安装联合冷备

`backup-installation` 接受安装输入、稳定操作 ID、位于安装目录之外的私有备份目录，以及每个保留 CA 的确切容器 ID、issuer、purpose、在线与离线目录、离线 root 私钥和密码文件。准备阶段核对已启用宿主、实际 provider issuer、CA 容器挂载、在线 issuer 与原离线 root 私钥对应关系；不接受用另一份目录冒充原 CA。备份中包含秘密，公开回执只返回操作、阶段和需独立保存的 manifest SHA-256。

操作先持久保存原身份，关闭容器自动重启并停写，保存和暂时收回普通运行角色的数据库 CONNECT 授权。数据库 owner 和受控管理员用于原样 dump 及切换到原只读角色后的 Ledger 验证。联合归档保留部署文件的原 UID/GID/权限、原保护材料、内容卷、S3 确切物理版本和 CA 在线/离线目录。未决对象继续保持未知；原 Ledger 历史逐页验证，不更换 HMAC 密钥。归档封存后按原权限恢复连接并重新观察宿主。

`restore-installation` 使用备份目录、独立保存的 manifest 摘要、新恢复操作 ID、目标管理员数据库连接，以及平台和每个已启用业务租户的 `accounts`（tenant_id、原 principal_id/login/password_file）。这是同址恢复：数据库名称/地址、安装路径、材料路径和内容路径保持原值；目标库必须为空，受限角色及原凭据须已恢复，外置材料父目录须存在。拒绝覆盖不同文件内容或已有业务库。恢复数据库使用单事务和持久操作标记，原角色授权在验证完成后恢复；原账户执行真实认证及授权核对，不以密码重置代替验证。

CA 原容器仍存在时核对原 image/command/mount 后启动；容器缺失时从封存元数据生成固定、受限的 step-ca Compose 服务，复用原不可变 image、挂载和数据库，不重新初始化 CA。自定义 Docker 网络及固定 image 属于需预先恢复的部署基础设施。任何材料、旧密钥、权限、网络或外部 S3 资格缺失均停在原检查点，不能宣称恢复成功。

`configure-host` 的 `channels` 变更接受严格的 Windows/Apple/Agent 配置、完整 provider 集合及 Apple 导入信任根。通道尚未就绪时保持关闭；可以先仅安装材料校验根，再由原材料 API 导入证书，最后启用通道。Windows 部署输入省略 `protocol_protection` 时，首次启用生成独立材料，已有通道沿用原材料；更换写钥必须走 `rotate-protection`。Apple 已建立的 `identity_seed` 不可被通道更新替换。所有文件输入在副作用前复制到按内容摘要命名的私有文件，应用摘要绑定实际材料字节；原输入文件随后变化不能改变已冻结的候选。

目录增加 `domains` 导航字段，指向经权限过滤的既有账户、Group、Scope、Policy、软件资源、Apple 组织及注册 owner；不复制这些领域的写状态。`GET /api/v1/agent-packages` 提供与匿名包目录一致的公开发布元数据，仍要求业务目录权限。`GET /api/v1/tenant-administration/provisionings` 提供平台可读的原开通回执；其中历史观察不能当作当前进程健康保证。

### 出站 Webhook 签名材料

运行配置只保留受限 `networks` 和原恢复数据库配置，删除 `keys/current_file/retiring` loader。签名材料由 webhook owner 加密持久化，投递授权在事务中读取当前 active/retiring 选择；这是直接生效的领域设置，失败候选不会替换仍有效的 active 密钥。网络配置仍由部署边界限定，可通过 `configure-host` 的 `webhook_networks` 变更受控应用。

`GET /api/v1/webhooks/materials` 返回网络配置摘要及公开版本状态。`POST` 同一路径接受 `reference`、`expectedRevision`、`configurationSha256`、`endpoint`、`networkReference` 和 `source`（`generate` 或 `import` 的 Standard Webhooks `whsec_` secret），要求近期真实会话、WebhookWrite 和 `Idempotency-Key`。响应和操作查询不返回秘密。`export-webhook-key` 由部署 operator 将指定版本交付到私有 `webhook-delivery-<operation>/delivery.json`；标准输出仅含公开回执。

接收方安全安装该 secret 后，部署进程向已批准的精确 HTTPS endpoint 发出 `rss-mdm.webhook-key-confirmation/v1` 请求，使用该候选的 Standard Webhooks 签名。接收方验证签名，再以相同密钥对下面的 UTF-8 字节计算 HMAC-SHA256，返回 `{"confirmationProof":"<standard-base64>"}`。行间为单个 LF，结尾没有 LF：

```text
rss-mdm.webhook-key/v1
<tenant UUID>
<reference>
<material revision>
<configuration SHA-256>
<challenge standard-base64>
```

该响应与请求签名使用不同消息，不能通过回显请求签名伪造确认。TLS 地址固定、无代理、无重定向，证书名字/根和网络边界均校验；失败保留原候选并至少一分钟后重试。普通运行角色无权写入 `confirmed`，也不能在 INSERT 时伪造确认。确认仅证明指定接收端在核验时持有确切候选，不代表业务事件已投递。

`POST /api/v1/webhooks/materials/transitions` 接受 reference、expectedRevision 和 action（`activate`/`revoke` 的 materialRevision，或 `retire_previous`），同样要求 Idempotency-Key。激活须有真实 receiver confirmation；当前被撤销时失败关闭，不退回旧钥。旧双签仍有未决投递或恢复时拒绝退出，已退出材料继续加密保留供历史及联合备份。公开 DTO 和接收合同见 [Webhook Materials schema](../../crates/webhook-service/schema/Materials.json)。
