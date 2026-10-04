# 运维与恢复

## 版本切换

当前版本只支持空库安装，以及完全一致的当前安装记录重放。 新 Agent V1（从当前 V6 完整重建）/ 软件 Resource V4 同样没有原库升级路径：旧签名任务、不可变定义、原始导入证据和结果不得重签、重编码或重算摘要。待处理任务和回执须由匹配旧制品、数据库与密钥的旧部署处理；排空队列也不会使旧 Resource 数据库可供新服务读取。新版本使用空库安装并重新注册新 V1 Agent（历史 V1 不兼容）；旧部署按历史证据保留和恢复。旧版本、前缀、缺失、未知、摘要修改或未完成的迁移记录均拒绝；不提供旧审计表导入或兼容迁移。拒绝时保留数据库及安装记录，不自动清库或重写摘要。

部署使用配套数据库、服务、Agent 协议及可信签名配置。管理客户端使用 Enrollment `/api/v1`、状态型设备命令 `/api/v1`、企业脚本计划及运行 `/api/v1/script-plans`。安装前显式配置审计 Plain 或 Ledger；Ledger 的 key ID 与受保护密钥文件必须由部署方提供，缺失或错误时拒绝启动。

恢复前停止全部写入实例，按同一备份时间点恢复数据库、内容卷和原 `native_protection_key_file`，确认服务账户可读且所有实例使用同一份 32 原始字节密钥后再启动。密钥备份应存入受控秘密存储并验证可取回；不要打印密钥或提交到代码/日志。当前不支持原地轮转或自行替换密钥；丢失原密钥后重新生成文件不能解密已有 native 数据，也不能解除 key identity 校验。原生输入认证或身份完整性损坏归为永久恢复失败，记录 `mdm_command_recovery_integrity_failure` / `native_input_integrity`，不持续退避；保留证据并从一致备份恢复，不能删除 guards 后重发变更。

内容上传和清理由 PostgreSQL 控制状态协调；恢复须使用配套数据库、完整物理内容和密钥，不能仅降级二进制。卷目录中的 `.<id>.lock` 是跨实例物理发布锁，删除后保留的标记阻止迟到写者重新发布，必须随完整租户目录一起备份，不得手工删除。暂存文件由对应持久对象意图回收。

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

`identity-audit` 使用与 Identity 同库的独立 consumer 连接，复用产品 Plain/Ledger 模式、实例、租户和 storage lineage/epoch。每批至多两条，与 Audit 连接池容量一致；有进展时继续；空闲或暂时失败后一秒再试。租约六十秒、发布五秒、结算一秒、安全余量一秒；关闭停止领取新批，等待当前组件调用结算，任务关闭限十五秒并受全局四十秒限制。中断不意味着回滚，重启保留原消息身份。

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

首次空库安装在任一单元中断后，当前安装器不会接续不完整基线。保留失败日志与数据库快照后，
由部署 owner 丢弃并重建这个尚无业务数据的安装库，重新按安装指南配置受限角色后运行 migrate；
若需保留先前状态，则恢复迁移前的一致数据库备份再安装。不得手工把 `mdm_migrations.complete`
改为 true，也不得删除 intent 或改写摘要来绕过准入。

迁移单元与 ledger intent 保留中断证据。SQL 或完成确认不确定时，先检查数据库与不可变 SQL，不把 complete=false 当作盲目重跑 DDL 的授权。拒绝基线或摘要不匹配时保留数据；不删除账本、自动清库或改写历史摘要。运行角色无 DDL，启动检查 schema、权限和 RLS；修复漂移不能从生产库覆盖固定 catalog。

当前准确迁移集合由二进制 --describe 与 [迁移源码](../../crates/app/src/migration.rs) 持有。升级须停旧写入口；回退恢复匹配数据库、制品、密钥与旧服务，不能仅降级二进制。数据库角色与首次安装见 [安装指南](installation.md)。Apple 证书、APNs 与 CA 排障见 [Apple 管理](../guides/apple-management.md)。

内容仓的 PostgreSQL journal 持有上传进度、对象版本、清单、额度和读 pin；服务端卷与 S3 都不能通过扫描目录或 bucket 重建业务状态。旧目录配置、上传 Saved JSON 和 checkpoint 不接受，也不自动迁移。全新安装须使用匹配 schema 和空内容 namespace；恢复旧部署时恢复匹配数据库、内容、密钥与二进制。

备份须保存数据库、`native_protection_key_file` 及清单引用的全部物理对象：卷模式保存完整租户目录，S3 模式保存确切对象版本及版本控制状态。停写后制作一致备份并联合恢复；只恢复当前 S3 key 的内容不足以恢复清单。后端身份和保护密钥标识在租户首次启用时固定，更改 endpoint/bucket/namespace/卷目录不能作为数据迁移方式。

S3 使用只读挂载的 access/secret/session token 文件；宿主在启动时安全读取并保存在内存，SDK 查询凭据时不执行磁盘 I/O。轮换后重启同一配置实例，静态 session token 的有效期由部署 owner 管理。私有 CA 文件有界读取且不接受符号链接；不提供关闭 TLS 校验的选项。Compose 现有 `runtime:/run/mdm:ro` 可容纳这些秘密，S3 模式不使用 content 卷；卷模式继续挂载持久 content 卷。

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

Agent 在固定 HTTPS origin 上匿名取得公开 `/api/v1/agent/enroll/trust`，不从它取得授权。更新先校验并持久保存 revision/CRL 水位，再通过系统机器 Root/CA 存储写入和读取确认；安装 ACK 仍须当前登记的真实 mTLS 与原幂等操作。仅删除该服务有持久 ownership 记录、且已退出完整批准集合的证书。首次 HTTPS 根通过受控部署渠道提供；新部署公开 JSON 也必须受保护，不能用本地测试占位材料。
