# 运维与恢复

## 版本切换

本版本使用全新数据库安装；后续租户登记、回执恢复查询和当前安装重放见[安装指南](installation.md#全新实例安装)。安装身份、组件清单、权限或 fencing 不匹配时保留数据库及安装记录，按实际失败原因恢复。

部署使用配套数据库、服务、Agent 协议及可信签名配置。管理客户端使用 Enrollment `/api/v1`、状态型设备命令 `/api/v1`、企业脚本计划及运行 `/api/v1/script-plans`。新安装默认使用审计 Plain，Ledger 须显式配置；Ledger 的 key ID 与受保护密钥文件必须由部署方提供，缺失或错误时拒绝启动。

恢复前停止全部写入实例，按同一备份时间点恢复数据库、内容卷和原 `native_protection` 引用的全部材料，确认服务账户可读且所有实例使用同一份 32 原始字节密钥后再启动。密钥备份应存入受控秘密存储并验证可取回；不要打印密钥或提交到代码/日志。加密写钥通过 `rotate-protection` 切换，不能直接覆盖原文件；丢失原密钥后重新生成文件不能解密已有 native 数据，也不能解除比较身份校验。原生输入认证或身份完整性损坏归为永久恢复失败，记录 `mdm_command_recovery_integrity_failure` / `native_input_integrity`，不持续退避；保留证据并从一致备份恢复，不能删除 guards 后重发变更。

内容上传和清理由 PostgreSQL 控制状态协调；恢复须使用配套数据库、完整物理内容和密钥，不能仅降级二进制。卷目录中的 `.<id>.lock` 是跨实例物理发布锁，删除后保留的标记阻止迟到写者重新发布，必须随完整租户目录一起备份，不得手工删除。暂存文件由对应持久对象意图回收。

Command、Inventory、Audit、Ledger 与产品 receipts 的完整结构/权限检查只在构造、显式启动和受控变更重新准入时执行。
变更相关角色、函数或结构前，停止相关写实例并排空事务，再执行受控变更；使用 access、
flow、command、software、租户注册、管理员初始化和 Identity 运行、维护入口各自实际连接重新验证，成功后才恢复接流。
目标数据库、角色或部署版本变化时停止并重建相关 runtime，使用新连接完成启动准入后才接流；验证失败保持停机。
业务操作仍检查租户、必要隔离和持久材料一致性，并传播真实 SQL 权限失败；
不承诺逐次调用发现管理员带外配置漂移，不支持滚动混跑旧、新契约。

## 就绪、停机与恢复

/livez 表示进程可响应。/readyz 要求启动 admission、首次有界恢复与投影通过，工作任务仍运行且尚未停机；不表示 backlog 已全部追平，健康查询不额外探测 IdP。

经授权的 `GET /api/v1/runtime/diagnostics` 查询当前实例的组件汇总，返回 `alive`、`ready`、`components` 和 `channels`。
管理员通过现有授权规则显式授予租户级 `runtime_diagnostics_read`；该权限不由设备读权限或授权管理权限隐式获得。
诊断查询为被动会话活动，不产生管理审计；认证或授权库不可用仍拒绝请求，审计依赖故障不替换普通查询响应，没有匿名诊断旁路。
公开健康探针只返回存活或就绪布尔值，详情和 `/readyz` 消费同一宿主聚合。

组件分别展示就绪原因、诊断 health、真实受控任务状态和适用的依赖、队列或进度。health 的 degraded/unknown 表示本次观测故障或缺失；
readiness 仍表达公开探针的既定条件，两者不能互相推断。入口暂停与依赖读取失败分开；
任务 running、已转发任务、服务就绪均不表示业务完成或设备实际效果。执行恢复只有受控任务仍运行、恢复扫描和派发首轮均确认成功且未停止时才就绪；确认空扫描/空领取也有效。
依赖扫描或派发轮次故障撤销就绪，后续成功轮次可恢复；停止信号或任一分支退出立即撤销就绪，在途事务仍按原预算结算。
可选通道及其子能力在 `channels` 中显示 `disabled / waiting / ready / degraded`，同时给出实际路由 `mounted`、阻断原因及已加载材料版本；不再作为核心组件影响 `/readyz`。材料已保存或已选择不代表当前进程已加载，更不代表网关入口或依赖操作可用。PKI 版本取自当前运行中的 verifier，签名与推送版本对应本进程实际加载的材料。
`trust_conflict` 表示配置与既有信任发生冲突，属于阻断状态；保留数据库、密钥和信任历史，核对 hostname、租户、用途与材料，不通过清空持久信任绕过冲突。

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

审计与业务状态在原 RSS 事务中直接提交。运行连接使用 `READ COMMITTED`，启动校验实际 writer 权限；Plain 不取得租户审计头锁，Ledger 在业务和 Outbox 锁之前取得所选链锁。提交未知沿原操作身份和原请求由业务回执恢复，不直接重执行业务，也不重新生成审计时间或复制回执。暂时缺失不能证明回滚；锁或读取超时继续保留未知状态。既有业务截止时间不续期，由原事务 owner 完成提交或回滚；这些资源边界不是吞吐或设备容量承诺。

Ledger 启动会校验既有链身份并认证有界记录窗口，同 key ID 配错密钥也拒绝启动。新空链没有历史密钥认证证据，部署方仍须保管最初配置的秘密。运行时不自动生成密钥、轮转或降级 Plain；当前部署不支持更换既有审计完整性模式。关键动作拒绝、敏感查询、多阶段最终结果及其重放与未知结果使用独立请求事实，在受保护响应释放前完成可靠提交；普通读取与轮询不写管理审计。`RollbackFailed` 与 `CommitUnknown` 均不是成功回滚证明，日志也不替代持久审计。
收到 `operation_rollback_unconfirmed` 时保留原 operation 身份及原请求，按同一锁协议重试/读取原回执；
不得更换 UUID 或把暂时 404 当作回滚证明。持续不可核对时停止自动重试并由部署 owner 检查业务、
最终审计记录的一致性，不补造记录。Agent 通道将它与 CommitUnknown 一并映射为 `operation_unknown`，
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

relay 的完整 messageId 保留类型前缀：`dispatch.<UUID>` 关联同 UUID 的 operation，`action.<UUID>` 关联企业任务 run；recovery 的 `target` 是设备文本 ID 的 SHA-256 scope，结合 `mdm_commands.devices` 定位。使用有设备读取权限的管理查询查看 command、最新 attempt 和 CollectionRun。`phase` 区分 claim、accept、settle 与 runner/scan；日志不携带预期值、原生正文或浏览器凭据。恢复后确认告警停止、同一 command 可继续收敛；终态任务不得因重启复活。启动核对当前候选安装账本与各能力的必要权限、租户隔离和可信函数，不比较全库结构快照；恢复验证见当前安装联合冷备。

安装失败保持服务停止并保留证据。回退指停止新部署后恢复原有独立部署及其一致数据库/密钥备份；新代码没有中央认证回退路径。仅在新候选和 smoke 通过后，按精确镜像身份、归档目录和专属缓存记录清理本任务废弃产物，不进行全局 prune。


## 请求与后台执行

配套网关对实际 TCP peer 的通用 `/api/` 请求执行每秒 10 次、burst 20 的 admission，登录仍使用
更严格的独立额度；转发头不能改写额度身份。已受理业务由原 Runtime 生命周期排空。关键动作及敏感访问必须可靠提交审计；普通读取和普通拒绝仅保留有界诊断。Inventory 和 Windows retention 先做只读候选检查，无过期任务时不追加审计。

Inventory、资产自动化、命令 relay/recovery 和原生协议维护由产品实例内唯一 PostgreSQL LISTEN 连接接收提交通知。连接只监听配置租户的独立通道，发送端从同一业务事务已绑定的租户派生通道；同租户多实例均可接收，无关租户不会被唤醒。通知仅携带闭合工作类型，不携带租户、设备或任务正文；业务事务提交后才投递，所有 worker 仍从持久状态重新读取、准入并领取。有进展立即继续，空闲等待通知或最近到期点，最长五秒补扫；既有错误退避独立保留。资产自动化成功动作后的 Reobserve 仍为二十毫秒，与五秒空闲补扫分别配置；已确认提交的短期重观察/重试可提前唤醒。初次 LISTEN 和重连完成后全部补扫，通知丢失、进程重启或多个实例均不改变持久事实的权威。`mdm_notification_connection.connected` 记录连接故障与恢复转换，SQLx自动重连完成也补记这对转换；不需要按通知数量推断完成量。

Compose 中 PostgreSQL 启动期每秒检查，稳定运行后每十秒检查。数据库健康检查不代表产品 readiness。
有候选时，Ledger 模式先取链锁，再锁业务行；Plain 直接使用业务锁。每次至多处理 32 个会话，事务六秒、周期调用七秒有界；
超时回滚或未知时保留原状态，下轮重新读取，Ledger 链锁不能移到业务锁之后。
监控网关 429、请求延迟、审计/retention 超时与数据库存储增长；这些是部署 admission 上限，不能解释为吞吐承诺。

## 安装失败与恢复

首次安装先持久绑定 instance、存储 target/lineage 与审计模式。每个组件的 SQL 变更和完成回执在同一数据库事务提交；进程中断或提交响应丢失后，使用原输入重试，安装器核对当前清单的精确已完成前缀并从下一单元继续。运行宿主仍只接受完整清单，不接纳部分安装。

摘要变化、缺失中间单元、重复回执、旧的不完整 intent 或安装身份不符均拒绝接续。保留数据库与原安装 journal，调查或恢复一致备份；不得改写 `mdm_migrations.complete`、删除回执、重签摘要或清空已有业务数据。当前不支持旧候选数据库升级；清单不匹配不能靠重试接入。运行角色无 DDL，启动检查 schema、权限和 RLS；修复漂移不能从生产库覆盖固定 catalog。

安装 journal 中的 Ledger 密钥是固定安装密钥。重放校验同时绑定原保护材料，缺失、损坏或替换时失败；恢复必须提供原密钥和一致备份，不切换新链、不重签历史，也不自动降级 Plain。该约束不提供同链 HMAC 换钥能力。

当前准确安装集合由二进制 `--describe` 与 [安装源码](../../crates/app/src/migration.rs) 持有。正常恢复要求数据库、候选制品、配置、内容与密钥共同匹配；清理前候选的数据库和备份不能直接接入清理后的候选。恢复旧候选时使用其匹配的原制品及一致备份，不能仅降级或替换二进制。数据库角色与首次安装见 [安装指南](installation.md)。Apple 证书、APNs 与 CA 排障见 [Apple 管理](../guides/apple-management.md)。

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

管理接口要求全设备 Credentials 权限，使用当前会话授权并在原 Audit 事务内复核。`GET /api/v1/pki/{purpose}/trust` 取得当前完整公开 revision；`POST /api/v1/pki/rotations` 提交 id、purpose、expected_revision 和包含一个 prepared issuer 的完整 candidate（revision+1），旧代次的公开身份与状态保持一致。先部署 prepared provider，再分发重叠信任。Windows 关联 CSP Get、Apple 关联 ManagedOnly ProfileList、Agent 认证信道的安装 ACK 形成对应设备回执；活跃登记仍缺回执时 activate 返回 conflict，原轮换保持 distributing。

`POST /api/v1/pki/{purpose}/rotations` 的 id 为原 rotation id，expected_revision 为当前 revision，action 依次为 activate、retire。prepare 返回 distributing；安装回执就绪后，一次 activate 完成校验与签发者切换，返回 activated；retire 返回 retired。各步骤仅递增一次 revision，不要求独立批准或批准后的第二轮 ACK。每个阶段保留稳定回执，未知提交沿原 id、action、expected_revision 和完整请求重试；先用公开 trust 核对现行事实，读取现行版本不替代原操作回执。每个 purpose 同时最多一个未完成轮换。激活后旧代次仅验证，新授权使用新代次；已冻结的签发/恢复沿原 CA。旧 issuer 仍有未知签发，或仍有未过期且未取得撤销发布证明的已签发证书时，不能 retire。重叠期由实际迁移/过期/撤销事实决定，不用固定等待时间绕过门禁。

Windows 未知签发通过 `POST /api/v1/pki/signing/recover` 提交原 attempt 与原 certificate chain；Agent 仅通过原 `agent-issuances/{id}/recover` 在原 owner 事务中一并恢复候选和公共签发记录。SCEP 沿原 attempt/notify 路径处理，不重新授权 consumed challenge。任何恢复均核对原 CSR/SPKI、CN/SAN、purpose、issuer、签发窗口和链，不换 CA、不换 jti、不创建替代证书。

在线撤销先在原登记/凭据 Audit 事务中立即生效，并写入实际 serial 的持久撤销队列。维护任务每 60 秒从各代次 CA 拉取 signed CRL，离开业务锁后调用 `/revoke`，失败保留 bounded backoff 任务。CA 接受 passive revoke 只表示 submitted；只有 serial 出现在经批准 issuer 签名的新鲜 CRL 中才记为 published。正式 SIT 的 issuer CRL 有效期为 168 小时、step-ca 每小时重新生成，吊销时立即生成，配置见[服务端 SIT 部署](installation.md#服务端-sit-部署)。根 CRL 30 天并在到期前 7 天由离线 owner 更新；缺失、过期、号码/时间回滚或同号异内容均拒绝认证。保留连接及 TLS 恢复仍逐次检查当前凭据映射。

共享 CA 的同一份 CRL 分别更新各用途记录；自动维护操作按用途区分，重放只更新公开吊销材料，不改变设备身份、信任 revision 或原签发回执。短周期 CRL 可用于专项测试，不作为正式 SIT 默认值。

维护前核对所有已启用用途已接收到 CA 最新 CRL，剩余有效期须覆盖预计停机及恢复余量；168 小时不是任意时刻都剩余 7 天。只停止 CA 时，已有有效证书可在原 CRL 有效窗口内继续通过产品校验，签发、续期及吊销发布暂停；产品内已撤销登记仍立即拒绝。整个环境停机时设备管理通信暂停。恢复先启动原 CA 和数据库，再启动产品服务；原维护任务从签名历史恢复并自动获取新 CRL，核对所有已启用用途就绪及原身份、撤销记录。即使旧 CRL 已过期，也不清库、重新注册或放宽过期/回滚检查。预计超过有效窗口时提前制定更长窗口或可用性方案，不能把过期清单当作宽限授权。

离线根或 legacy issuer 的 CRL 使用 `POST /api/v1/pki/crls` 发布单一 operation、purpose 和 publications 数组（1–16 项，每项 issuer、crl、root_crl，base64 DER）。同 root 的所有代次共同采用同一 root CRL，集合内冲突拒绝；不把根私钥带入在线宿主。刷新按同 purpose 完整集合校验、原子发布；停机造成多个 issuer CRL 过期后可整组恢复。备份/恢复必须保留 CA 数据库、原密钥身份、serial/token 使用记录、MDM 数据库和 Audit/Ledger；成功签发与撤销发布的未知结果仍沿原记录恢复。

设备 CA 在正式 SIT 使用 `deployment/sit.compose.yaml` 的 `step-ca`；开发/T2 使用 `deployment/compose.yaml` 的 `pki` profile。SIT 使用一个 CA 实例及数据库，各 purpose 保留独立 provisioner 和产品记录；在线 `MDM_PKI_ROOT` 只含中间 CA 加密密钥、公开根、配置、模板及 CA 数据库，根私钥和独立解密秘密放在未挂载的离线目录。step-ca 原生 `kms` 配置选择加密文件 SoftKMS 基线，`key` 可替换为受支持 KMS/HSM URI，由 CA 部署 owner 提供对应访问凭据与验收；MDM 不读取 KMS 或根私钥。非 step-ca 企业 CA 路线登记为 #2680。

每份 CA 数据库同一时间只允许一个写入者。冷备接管先停止并移除旧 `step-ca` 容器，核对 `compose ps --all --quiet step-ca` 为空并确认旧主机被隔离，再以同一绝对存储路径和 `MDM_PKI_PUBLISH` 原端口启动独立 standby project。持久 provider origin、issuer、kid、数据库和 token 记录保持原身份；无法证明旧主隔离时不能启动新写入者。候选验证复用这份 Compose，产品 profile 仅公开 Nginx 网关端口，网关终止控制台与 enrollment/management/Agent 的 TLS/mTLS，并代理精确配置的 SCEP 路径；其它 CA API 和 Rust 内部 HTTP 端口不公开。

Apple 的 challenge/notify webhook ID 和 HMAC 秘密属于稳定协议配置。新 CA 代次须沿用该 purpose 的受控 webhook 身份、回调地址和签名模板，先验证原生回调再准备/激活；不能直接采用新建 provisioner 随机产生的 webhook 身份替换已有部署配置。HTTPS、SCEP 解密、Profile 签名及 APNs 密钥仍各归原 owner。

`device_pki_attention` 每分钟输出公开 issuer 摘要、证书到期、CRL nextUpdate 与 unpublished 数量：issuer 剩余 30 天、根剩余 90 天、issuer CRL 剩余 120 秒、根 CRL 剩余 7 天或撤销尚未发布均触发。`device_pki_maintenance_failure` 按累计失败次数的幂次记录依赖故障；CA 运行或 `/revoke` 成功不代表 CRL 已发布。告警接入使用这些结构化事件并核对签名发布及原队列；密钥取回失败同时由 step-ca 的受限日志定位。所有服务实例保存历史 CRL 水位，退休后再引入同一 CA 也不能回滚已接受的号码或内容。

服务端在固定 HTTPS origin 上通过 `/api/v1/agent/enroll/trust` 匿名提供公开信任材料，该接口不授予授权；安装 ACK 仍须当前登记的真实 mTLS 与原幂等操作。首次 HTTPS 根通过受控部署渠道提供；新部署公开 JSON 也必须受保护，不能用本地测试占位材料。Agent 本机信任存储及配置更新操作由 [rss-mdm-agent 服务部署指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/local-service-lab.md&version=GBdevelop) 持有。

## 恢复凭据轮换、保留与恢复

凭据专用密钥环与 `native_protection` 分开管理。更换写入密钥时，将新旧密钥同时加入 `key_files` 并切换 `active_key`，重启后后台分批重加密，材料版本和有效性不变。移除旧密钥前确认没有剩余密文引用它；启动时校验持久密钥身份，缺失或错误密钥拒绝启用。接收证书更新独立于存储重加密：保留尚有执行或 FileVault escrow 需要的旧接收私钥，先更新端上的 escrow profile，再退出旧证书。

失效密文满 90 天后分批清除，元数据和审计保留。当前材料及未核实操作需要的材料不清除；后台同时清理已结算原生命令的秘密输入副本。失败以 `recovery_credential_maintenance_failed` 闭合诊断报告，不打印材料或密钥。数据库删除不代表历史备份已删除，备份沿用部署自己的保留策略。

停写后联合备份数据库、凭据密钥环、接收私钥及原有 native protection/内容材料。恢复使用对应密钥，重新检查当前登录授权、注册世代、撤销状态和保留期限。数据库与密钥重启/备份验证只证明服务端能按授权读取正确材料；PRK 解锁、Recovery Lock、Windows 密码登录及 BitLocker 实际恢复另由真机验收证明。

### 原生加密写钥切换

`docker compose -p rss-mdm -f /absolute/candidate/deployment/production.compose.yaml run --rm --no-deps --user 10001:10001 --entrypoint /usr/local/bin/rss-mdm-installer init rotate-protection --config /var/lib/rss-mdm/private-rotation.json` 接受 `installation`（原部署输入）、`purpose`（`native` 或 `windows`）和稳定 UUID `operation_id`。该一次性维护命令与其它维护操作互斥。操作先在最终保管目录生成新钥并保存每个宿主的两个不可变输入：第一阶段让全部实际进程读取新旧钥，第二阶段才切换新密文写钥。每个阶段都要求 HTTPS 返回确切宿主、操作、版本、摘要与新进程观察；失败使用原 operation ID 重试，不能手工跳过剩余宿主。

写钥切换完成后，每次调用以有界领域事务重加密 APNs/Profile/Managed Apple Account、任务签名私钥和 S3 凭据；`rewrapping` 表示还需继续用原输入调用，`complete` 表示该轮切换和上述运行材料批次已完成。私钥身份、材料版本、签名信任、ACK、原请求指纹和证书均不改变。中断可重放，单批失败回滚。

完成回执始终标记 `historicalKeysRetained=true`。历史原生输入、协议回执、物理内容块和备份仍可能引用旧加密钥，不能仅凭运行材料批次为零就删除旧钥。稳定比较钥另有持久身份用途，密文轮换不表示比较 HMAC 轮换。恢复须联合取回全部仍被记录或备份引用的材料；此流程不会自动退出旧钥，也不会修改固定安装 Ledger HMAC。

Windows 保护配置现在使用 `protocol_protection`，包含 `active_file`、`historical_files`、`fingerprint_file`。Windows 轮换先向所有启用 Windows 的宿主分发读钥，再切换写钥并分批重包注册秘密；固定 fingerprint 维持原注册/续期配置身份。旧钥继续保留供历史与备份恢复，完成写钥切换不表示旧钥可以删除。

### WNS 凭据与宿主应用

`POST /api/v1/windows/wns` 使用真实业务管理员会话、`RegistrationConfigurationWrite`、最近认证和 `Idempotency-Key`；正文是 `expectedRevision`、`packageFamilyName`、`sid`、`clientSecret`。Windows owner 加密保存候选，普通服务没有更新资格状态的数据库权限。`GET /api/v1/windows/wns` 返回当前 revision、期望版本和公开版本列表；`/api/v1/windows/wns/operations/{id}` 返回带 kind 的原操作回执。两者都不返回 SID 或秘密。`POST /api/v1/windows/wns/revoke` 接受 `expectedRevision`、`materialRevision` 和独立 `Idempotency-Key`，撤销后运行消费者拒绝该版本，旧操作可重复查询。正式 DTO 见 [WNS schema](../../crates/windows-channel/schema/Wns.json)。

一次性维护命令调用固定 Microsoft OAuth 入口验证候选，保存资格时间及失败类别；失败至少一分钟后才重试原候选。成功后导出运行配置，由运维重建对应服务，运行配置为 `push: {"revision": N}`，删除旧秘密文件 loader。相同 PFN/SID 的秘密轮换沿用原设备通道绑定，不要求设备因服务器秘密变化而重新注册；改变应用身份产生不同绑定，等待设备的真实 PFN/ChannelURI 查询结果。资格通过仅证明 OAuth 凭据在核验时可用，不证明离线设备收到唤醒。推送租约复核原版本仍被选择且未撤销。

设置目录 `/api/v1/settings/catalog` 和平台目录 `/api/v1/tenant-administration/settings/catalog` 使用 [SettingsCatalog schema](../../crates/management-http/schema/SettingsCatalog.json)。`configured` 只描述领域已有配置，`loaded` 只描述当前进程装载，`pending` 要求宿主应用或其他领域动作，`unknown` 明确要求 owner 观察；这些状态均不等同于真实设备验收。权限过滤先于领域读取，平台会话不会转换为业务会话。

### 租户首次配置

正式业务会话通过 `GET /api/v1/settings/first-use` 恢复本租户选择与当前进度；读写分别要求注册配置读写权限，原领域权限继续控制事实可见性和配置动作。平台会话与 API key 不能进入。公开合同见 [FirstUse schema](../../crates/management-http/schema/FirstUse.json)，全部设置入口仍由原设置目录提供。

`PUT` 沿用 `Idempotency-Key`，提交 `expectedRevision` 和完整 `intent`。通道可选 Agent、Windows MDM、macOS MDM；能力决定为 `configure` 或带非空理由的 `skip`，未纳入本轮的可选能力不阻塞。保存草稿使用 `completionRequested=false`；确认完成必须明确提交 `true`，后端核对本次选择的必要条件。所选通道及其必选材料不可跳过。安装包与任务签名单独选择，选择本身不会修改通道准入或配置。

已保存、当前进程加载和能力就绪分别表达；未知、无权限、故障或等待宿主应用不会通过。完成意图持久保存，`canComplete` 和 `complete` 每次按领域事实重算；后续过期或暂停可能使当前完成判定变为 false，原意图和审计历史保留。观察不承诺全局原子健康快照或真实设备效果。

冲突后读取当前 revision 再由管理员决定；提交未知时查询 `GET /api/v1/settings/first-use/operations/{operationId}` 或使用原 ID 和原正文精确重放。回执表达原意图版本，查询未发现不证明回滚；已提交回执不会因后来材料失效而被重新判失败。不得换 ID 盲重试、清库或重做初始化。

### SMTP 固定资格投递

部署输入 `mail_profiles` 给出受限 profile ID、`hostname`、确切 `address`、`tls`（`implicit` 或 `starttls`）和 `ca_file`。普通服务只提交 profile ID，不接收任意服务器地址或 CA 管理材料。`POST /api/v1/smtp` 接受 `expectedRevision`、`profile`、`sender`、`recipient`、`username`、`password`，要求最近认证的业务管理会话、注册配置写权限与 `Idempotency-Key`。这一动作授权发送一封固定资格消息，不接收主题、正文、附件或额外收件人。

邮件 owner 加密保存凭据；一次性维护命令对精确地址验证 TLS 名字、认证并实际投递。STARTTLS 失败不会降级，TLS 后重新 EHLO，再执行 AUTH PLAIN。DATA 发送前提交持久检查点；服务器明确拒绝与连接中断/响应丢失分别记录，未知结果不自动重投。`GET /api/v1/smtp/operations/{id}` 查询原操作，`GET /api/v1/smtp` 返回版本及选择状态。`accepted` 仅表示 SMTP DATA 取得 250 回应，不证明收件箱送达。正式 DTO 见 [Mail schema](../../crates/mail-service/schema/Mail.json)。未知操作应按原 Message-ID 从邮件系统核对，不能用新操作掩盖原结果。

实现依据 [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207)、[RFC 4954](https://www.rfc-editor.org/rfc/rfc4954) 和 [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)。不新增通知订阅产品。

### CA 准备及回调身份

普通部署使用一份 `step-ca.json`，由 Compose 的一次性 `init` 调用 `initialize-ca`；输入及命令见[设备 PKI 配置](installation.md#设备-pki-配置)。只管理内部 CA 地址、公开信任材料和初始化管理身份；用途名称、密钥、模板、SCEP 解密身份及回调自动准备。管理员凭据不会导出到服务或网关。

初始化将原操作、生成密钥及远端结果保存在受保护的配置目录，重放复用原操作，并通过认证 CA 接口重新核验 provisioner、模板及 webhook ID/secret。已存在但不同的资源拒绝覆盖，不删除重建。已有租户、设备、签发记录、协议保护材料和信任轮换状态不被初始化重置；新增 CA 代次仍须通过业务 PKI 发布、设备确认和激活流程。

管理证书和私钥续期、根 CRL 续发后，更新输入目录的原文件并重跑 `init`；管理凭据刷新不改变设备 CA 身份，根 CRL 更新作为一次配置导出，保留原信任 revision 和设备历史。根证书替换仍须显式 CA 轮换，不能当普通刷新。

SCEP 解密证书距到期不足 30 天时，同一 `init` 自动准备新解密身份并更新原 provisioner，保留原 webhook ID/secret、设备信任和设备证书。更新前核验原用途策略，持久保存新材料；结果未知时重放从原材料及认证 readback 恢复。运行服务不持有更新权限；运维按证书健康状态执行一次性 `init`，不新增常驻控制器。

首次创建 SCEP 解密身份使用 CA 的受限签发凭据，不读取 CA 签发私钥。签发意图先持久化；响应不确定时保留原申请并停止，禁止重新生成密钥或自动重签。运维从原 CA 记录找回匹配原 CSR 的证书，核对签发者及公钥后恢复到原操作的 `scep-encryption/identity.pem`，再重放。该目录及 CA 数据库属于同一冷备恢复集。

SCEP 公开域名与内部 CA 地址独立；网关只代理实际生成的精确 SCEP 路径，管理接口保持内网。step-ca 0.30.2 首次增加 SCEP 后用普通 Compose 重启一次 CA。初始化及 GetCACaps/GetCACert 通过只证明服务端配置，不代表真实设备注册或回调交付已经通过。实现依据 [固定 step-ca admin client](https://github.com/smallstep/certificates/blob/v0.30.2/ca/adminClient.go)。

Apple 的 `identity_seed` 永久保留原 challenge/notify ID，实际凭据放在 issuer 绑定的 `webhooks` 集合。Agent bootstrap 冻结签发者，切换活跃 CA 后原请求仍沿原 CA 完成；新请求在事务内复核当前活跃 CA。未知签发不因超时或设备清理完成而解除退役门禁。

`rotate-protection` 另支持 `oidc_credentials` 和 `recovery`：复用先分发读钥、再切换写钥的宿主阶段；OIDC provider 密文由固定 Identity 依赖的原领域方法在租户事务内重加密，恢复凭据由原 recovery owner 分批重包。OIDC state 签名、恢复 RSA recipient、原凭据身份及操作摘要保持不变。旧读钥继续保留用于历史、未决操作和备份；`complete` 不能解释为可以删除历史密钥。行锁超时保留原操作重试，不把暂时锁住的密文算作迁移完成。

### OIDC 与恢复凭据宿主配置

`configure-host` 使用安装输入、稳定 `operation_id`、`host_id`、`expected_revision` 和封闭的 `change`。`{"kind":"oidc","settings":...}` 的 settings 包含 `group_facts_max_age_seconds`、`return_targets`、`assurance_profiles`、`private_providers`。首次启用在受保护的操作目录生成独立 state 签名和 provider 凭据保护材料；后续设置变更保留原密钥。提供方客户端配置仍由原 Identity 管理 API 写入。宿主入口的 `oidcEnabled` 根据实际加载配置生成，平台会话不转成业务会话。

`{"kind":"recovery","recipient":{"kind":"generate"}}` 生成独立 RSA escrow recipient 和专用保护材料；也可用 `{"kind":"import","certificate_file":"...","private_key_file":"..."}` 导入原 recipient。该证书只用于恢复材料加密，不是设备 CA。新导入检查证书、用途、有效期及私钥匹配；替换保留原 recipient 私钥，历史密文与未决设备响应继续按原身份读取。过期 active recipient 拒绝生成新恢复任务，不阻断旧密文解密。

两种变更均先持久保存候选和原操作，再重启真实宿主并核对 HTTPS 观察。开通回执记录 requested/applied revision、当前观察和失败原因；失败保留原有效宿主并沿原配置操作恢复，不能把写入配置文件当成启用成功。

`initialize-ca` 将所有已核验的 CA 材料作为一次宿主配置导出，重复执行不增加 revision。后续启用通道自动接入这些材料，保留原协议种子与旧凭据。原逐用途部署命令已移除，既有操作目录和材料仍纳入备份与恢复。新增 CA 代次由真实业务管理会话通过原 PKI API 发布、等待设备确认并激活。缺少其他材料的设备通道不会被自动标为就绪。Agent bootstrap 在创建事务内选择数据库当前 active issuer，并从已装入的精确 issuer→SCEP 地址集合选路；重启不会把旧配置文件里的 active 标记重新当作权威。

### 当前安装联合冷备

`backup-installation` 接受安装输入、稳定操作 ID、安装目录之外的私有备份目录，以及每个保留 CA 的 issuer、purpose、configuration_file、在线/离线目录、离线根钥及密码文件。运维先停止全部写服务；准备阶段校验原安装、宿主记录及 CA 在线证书与离线根钥关系，数据库连接屏障拒绝仍有写连接的备份。产品不读取或控制 CA 容器。备份含秘密，公开回执仅返回操作、阶段及 manifest SHA-256。

运维先用 Compose 停止全部相关后端、网关和 CA 写入服务；产品备份命令不控制容器。命令持久保存原身份，验证无业务写连接，保存和暂时收回普通运行角色的数据库 CONNECT 授权。数据库 owner 和受控管理员用于原样 dump 及切换到原只读角色后的 Ledger 验证。联合归档保留 Docker 卷内固定服务 UID/GID/权限、原保护材料、内容卷、S3 确切物理版本和 CA 在线/离线目录。未决对象继续保持未知；原 Ledger 历史逐页验证，不更换 HMAC 密钥。归档封存后按原权限恢复连接并重新观察宿主。

`restore-installation` 使用备份目录、独立保存的 manifest 摘要、新恢复操作 ID、目标管理员数据库连接，以及平台和每个已启用业务租户的 `accounts`（tenant_id、原 principal_id/login/password_file）。这是同址恢复：数据库名称/地址、安装路径、材料路径和内容路径保持原值；目标库必须为空（用 `TEMPLATE template0` 创建，避免继承 Timescale 对象），受限角色及原凭据须已恢复，外置材料父目录须存在。拒绝覆盖不同文件内容或已有业务库。恢复数据库使用单事务和持久操作标记，原角色授权在验证完成后恢复；原账户执行真实认证及授权核对，不以密码重置代替验证。

CA 的镜像、网络、卷、启停与恢复由原运维 Compose/Kubernetes 声明负责。产品命令只校验所提供的在线/离线材料、恢复数据和身份，不读取 Docker inspect，不重建容器。`restore-installation` 完成后，先用交付的部署 renderer 重新生成网关配置。安装工具仅恢复 `deployment.json`、TLS 材料和公开配置，不生成 Nginx 语法。按原部署环境先恢复 CA，再运行以下命令。这里使用标准安装卷路径；自定义安装须替换为原 `deployment.gateway_directory`：

```bash
docker compose -f deployment/production.compose.yaml up -d --no-deps server web
docker compose -f deployment/production.compose.yaml run --rm --no-deps --user 10001:10001 --entrypoint python3 init /usr/local/lib/rss-mdm/render_gateway.py --root /var/lib/rss-mdm/runtime/gateway
docker compose -f deployment/production.compose.yaml run --rm --no-deps --user 10001:10001 --entrypoint cat init /var/lib/rss-mdm/runtime/gateway/gateway-ports.compose.yaml > ./gateway-ports.compose.yaml
docker compose -f deployment/production.compose.yaml -f gateway-ports.compose.yaml run --rm --no-deps --entrypoint nginx gateway -t -c /run/gateway/nginx.conf
docker compose -f deployment/production.compose.yaml -f gateway-ports.compose.yaml up -d --no-deps gateway
```

Compose 仍需原部署环境及秘密文件。网关默认绑定 `0.0.0.0`；原部署使用其它绑定 IP 时，渲染命令必须显式传入相同的 `--publish-address`。然后沿原维护输入执行 `prepare-hosts`，核对每个公开入口的真实 HTTPS 观察及原身份，再检查实际认证和用途 CA。

`configure-host` 的 `channels` 变更接受严格的 Windows/Apple/Agent 配置、完整 provider 集合及 Apple 导入信任根。通道尚未就绪时保持关闭；可以先仅安装材料校验根，再由原材料 API 导入证书，最后启用通道。Windows 部署输入省略 `protocol_protection` 时，首次启用生成独立材料，已有通道沿用原材料；更换写钥必须走 `rotate-protection`。Apple 已建立的 `identity_seed` 不可被通道更新替换。所有文件输入在副作用前复制到按内容摘要命名的私有文件，应用摘要绑定实际材料字节；原输入文件随后变化不能改变已冻结的候选。

目录增加 `domains` 导航字段，指向经权限过滤的既有账户、Group、Scope、Policy、软件资源、Apple 组织及注册 owner；不复制这些领域的写状态。`GET /api/v1/agent-packages` 提供与匿名包目录一致的公开发布元数据，仍要求业务目录权限。`GET /api/v1/tenant-administration/provisionings` 提供平台可读的原开通回执；其中历史观察不能当作当前进程健康保证。

### 出站 Webhook 签名材料

运行配置只保留受限 `networks` 和原恢复数据库配置，删除 `keys/current_file/retiring` loader。签名材料由 webhook owner 加密持久化，投递授权在事务中读取当前 active/retiring 选择；这是直接生效的领域设置，失败候选不会替换仍有效的 active 密钥。网络配置仍由部署边界限定，可通过 `configure-host` 的 `webhook_networks` 变更受控应用。

`GET /api/v1/webhooks/materials` 返回网络配置摘要及公开版本状态。`POST` 同一路径接受 `reference`、`expectedRevision`、`configurationSha256`、`endpoint`、`networkReference` 和 `source`（`generate` 或 `import` 的 Standard Webhooks `whsec_` secret），要求近期真实会话、WebhookWrite 和 `Idempotency-Key`。响应和操作查询不返回秘密。`export-webhook-key` 由一次性维护命令 将指定版本交付到私有 `webhook-delivery-<operation>/delivery.json`；标准输出仅含公开回执。

接收方安全安装该 secret 后，一次性维护命令向已批准的精确 HTTPS endpoint 发出 `rss-mdm.webhook-key-confirmation/v1` 请求，使用该候选的 Standard Webhooks 签名。接收方验证签名，再以相同密钥对下面的 UTF-8 字节计算 HMAC-SHA256，返回 `{"confirmationProof":"<standard-base64>"}`。行间为单个 LF，结尾没有 LF：

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

## 单机部署的重启与恢复边界

Compose 拓扑与配置归属见[安装指南](installation.md#单机部署设计与配置归属)。gateway、web、server 独立部署，只有 gateway 发布 443。配置变更沿原 configure-host 导出运行输入；运维只重建受影响服务，再核对 requested/applied revision、材料摘要和实际进程观察。材料保存不代表运行生效。

完整服务端 SIT 使用[安装指南的 SIT 流程](installation.md#服务端-sit-部署)与 `production.compose.yaml` + `sit.compose.yaml`；基础四服务启动不代表 CA、内容存储与设备通道已接通。CA/RustFS 已存在时保留其卷、身份、桶与凭据，不重新生成。测试设备准备和设备效果不纳入服务端部署完成判据。

静态资源更新只重建 web；后端材料应用只重建对应 server；SNI、HTTP 路由或 TLS 配置变更先执行 gateway 的 `nginx -t -c /run/gateway/nginx.conf`，再 reload 或独立重建 gateway。通过 configure-host 提交的变更若更新了 runtime binding，还须重建对应 server 加载新 binding 并核对应用回执。三个服务不存在共享网络命名空间的成对重建要求。

服务 TLS 变更后分别检查网关与原生设备入口的证书链、主机名及实际连接；设备证书仍由后端验证，不借助代理头。CA、SCEP/webhook 和根/issuer CRL 变化按各自原 owner 验证，单机上的 DNS/容器健康不替代外部设备网络检查。APNs/Profile/WNS 等材料使用领域版本与受控应用流程，不恢复启动秘密文件 loader。

备份使用上节 `backup-installation` 的停写与联合归档流程，恢复使用 `restore-installation`，不把正在运行的数据库/对象目录简单打包当作一致备份。CA 原数据库同时只能有一个写入者；停机、备份和接管均须证明旧写入者已隔离。归档、独立 manifest 摘要及秘密保存在异机受控介质，单机本地副本不能覆盖整机丢失风险。

当前恢复只支持上节明确的同址条件，不提供 HA、异址自动灾备或未经实测的 RPO/RTO。CA 镜像和数据库由原运维声明恢复，产品输入覆盖每个 `(purpose, issuer)` 并验证材料；共享 CA 的用途记录与物理 CA 必须一致恢复；跨机和外部供应方恢复需要独立演练，不能从基础种子安装结果推导通过。

恢复测试保留原账户、设备、issuer/kid、内容版本及 Ledger/保护材料，不能用换钥、重新注册、清库或重置密码代替核验。

真机与故障记录使用[验收清单](installation.md#真机验收清单与证据)，区分服务恢复、历史身份可验证和终端实际恢复；缺材料或结果未知时保留原检查点与 blocked/unknown，不发布成功结论。

## Compose 维护材料与数据库 TLS 续期

维护命令复用初始化镜像，显式覆盖入口并使用 UID10001，不启动常驻进程。配置、材料和数据库权限仍属于各领域；产品命令不管理容器。秘密通过 stdin 导入卷内指定的 0600 文件：

```sh
docker compose -p rss-mdm -f /absolute/candidate/deployment/production.compose.yaml run --rm --no-deps --user 10001:10001 -T --entrypoint python3 init -c 'import pathlib,sys;p=pathlib.Path("/var/lib/rss-mdm/maintenance.json");p.write_bytes(sys.stdin.buffer.read());p.chmod(0o600)' < /absolute/private/maintenance.json
# 任一现有维护命令均使用相同入口；这里执行一次配置准备与实际进程观察。
docker compose -p rss-mdm -f /absolute/candidate/deployment/production.compose.yaml run --rm --no-deps --user 10001:10001 --entrypoint /usr/local/bin/rss-mdm-installer init prepare-hosts --config /var/lib/rss-mdm/maintenance.json
```

`prepare-hosts` 只执行一次供应方核验、材料版本投影与真实 HTTPS 观察，不启动或重启服务。材料应用时保存原 operation，导出配置后受控重建 server，再重放原操作或运行 prepare-hosts；实际版本未加载时保持 pending。所有原生设备流量都从 gateway 已配置的 HTTPS 域名和端口进入。

`rotate-protection` 的 distributing/activating 阶段同样先导出文件，保持原 operation；运维分阶段重建服务，再重复原命令取得真实观察，全部宿主确认后才切换写钥及重加密。不会自动恢复旧容器；需要回退时由运维恢复先前已确认的配置和 Compose 版本，保留原密钥。

PostgreSQL 和网关服务器证书由部署方签发、保管与续期。替换 PostgreSQL 输入后用 Compose 重建 postgres，保留原 CA 信任及数据库秘密。网关使用 `configure-host` 的 `change.kind=gateway_tls`，提交新证书、匹配私钥和信任文件；运维重建 gateway 加载新证书，并重建对应 server 加载本次变更的 runtime binding，再用原操作核验实际 HTTPS 与应用回执。容器网络独立不改变当前回执对 server binding 的核对要求。没有内置证书签发器或续期后台任务。

CA 联合备份的每个 authority 提供 purpose、issuer、configuration_file、online_directory、offline_directory、root_private_key_file、root_password_file；所有路径是维护容器中明确挂载的文件。运维先停止相应 CA，再运行备份/恢复；产品校验实际 issuer 与根钥关系并归档文件，不持有容器 ID、镜像、网络或 Docker 卷元数据。离线根材料只交给受控维护，不进入在线 CA 或业务服务。

## 遥测积压、维护与恢复

遥测批次回执区分产品已接收、目的端已准入和结果未知；当前资产投影、历史可见性和聚合窗口进度分别查询。`published` 不表示当前资产已经更新，也不表示指定汇总窗口已完成。结果未知时使用原 batch ID 和原始内容查询或重放；同 ID 不同内容会冲突。凭据或策略变化阻止新输入，已经原子接收的内容继续按封存上下文结清。

ready 状态同时检查遥测 worker 和实际后端。诊断提供待交付、未知、受阻和维护积压数量；设备字段健康 API 提供采样质量计数、保留维护时间及阻塞原因。自动维护固定每个精确历史序列的策略版本和操作身份，按有界步骤推进 cutoff 与裁剪；已经接收的批次未结清时暂不推进。维护结果未知继续原身份，缺失和失败不补零。手动重算、删除恢复及流关闭通过同一 RSS 维护接口执行，调用时重新检查设备 Scope 和敏感字段权限。

联合备份请求必须列出全部启用的遥测安装请求。产品主库、遥测 PG 数据库与 ClickHouse 数据先停写；备份清单包含每个数据库子归档、安装身份、原生 ClickHouse 归档以及原配置和秘密。停写时先撤销 ClickHouse 写入和维护权限，阻止控制库重连，再关闭该安装只读 guard 的缓存连接；其它活跃客户端仍阻止备份。ClickHouse PG 控制库和数据必须成套备份、成套恢复。恢复使用同址、原操作身份和受校验清单，完成数据恢复后重新准入，失败重新停写。不要单独恢复控制库、删除未知备份回执或替换服务器配置来绕过冲突。

恢复窗口由字段绑定的不可变保留策略限制，普通资产值没有 TTL。现有实现不承诺在线存储切换、HA 或未经实测的 RPO/RTO；真机采样与离线缓存由终端实现提供独立验收。

当前开发基线的自有布局直接替换；不提供历史库迁移或兼容 reader。已有开发数据库、凭据和
journal 必须保留：新布局使用新建实例，不能修改旧安装账本的版本或摘要来绕过检查。
同一当前制品的重复安装、失败恢复及权限检查仍须成立。

## 默认遥测分区维护与初始化恢复

标准 Compose 的 `maintenance` 在启动及每小时调用 `maintain-default-telemetry`，使用原安装状态准备 UTC 当天起未来 8 天的日分区，并覆盖前一天的补传窗口。手动恢复使用同一安装输入：`rss-mdm maintain-default-telemetry --config <installation-input.json>`（具体参数以二进制 `--help` 为准）。重复调用复用当天的操作身份及数据库回执，不安装新后端、不改变保留策略。

准备分区允许现有 runtime 连接存在。创建分区仍需父表锁；锁等待有界，超时事务回滚，释放阻塞锁后重试原操作即可。维护失败时检查 PostgreSQL 锁、安装状态卷和凭据；不要给业务 runtime 授予 DDL 权限。物理 chunk 转换仍须停写，逻辑保留沿用原保留执行器。

`initialization_authorization` 表示原账户授权依据失效；`initialization_content` 表示内容供应未就绪；`initialization_conflict` 表示未完成对象已发生变更；`initialization_telemetry_backend` 表示遥测依赖缺失。服务每分钟恢复已保存意图，内容部分上传和未知提交通过原 upload/operation 回执继续。先恢复依赖或处理已变更对象，再观察运行诊断；不删除基线行或回执来重置部署。

原生设备验收仍依赖 #2862 Agent capability 修复候选和 #2728 平台矩阵。服务端 T1/T2 结果不能代替设备证据，也不能手工补 capability 声称通过。

### 可选通道状态

`/livez` 表示进程存活，`/readyz` 只判定核心管理服务。授权的 `/api/v1/runtime/diagnostics` 在 `channels` 中报告 Apple、Windows、Agent、WNS、Agent bootstrap 和 signing 的 disabled/waiting/ready/degraded、路由挂载状态、闭合原因和已加载材料版本。通道故障不会自动摘除管理面；数据库、共享保护根、身份绑定及核心完整性失败仍按硬依赖处理。

缺组织 APNs/Profile 时，先在 Apple 材料页申请/导入并选择版本，然后 prepare-hosts、重建 server、再次核对实际观察。过期或撤销材料拒绝相关操作；缺 TLS/设备信任网关拒绝相关入口。WNS 不可用时 Windows 轮询可继续，bootstrap 或签名不可用时仅拒绝依赖这些能力的操作。真实设备结果与宿主 ready 分别验收。

入口退役同时检查仍可使用的注册配置和未完成的原生 Agent 安装。新任务在接受时冻结当前发布的首选地址；策略和软件身份不绑定地址。已下发任务保留原下载 URL，完成、撤销或失效前保留其入口。撤销注册配置不会取消已接受的注册授权，已有授权须完成、显式取消或到期。连接状态的 `retirementBlockers` 分别报告注册材料和原生安装的阻断数量。Windows/Apple 原生注册与 SCEP 地址仍须按各原生配置的生命周期维护。

#


### 配置状态与完整历史

SMTP、存储连接和 WNS 的当前状态入口分别为 `/api/v1/smtp`、`/api/v1/storage/connections`、`/api/v1/windows/wns`。响应提供 head revision、当前选中引用、versionCount、current/latest；内部宿主摘要可额外读取实际 applied 引用，不通过历史第一页推断当前状态。

各入口追加 `/versions` 即为版本历史，接受 `limit/cursor`，返回 `items/nextCursor`，固定 revision 倒序，默认 64、最大 200。当前版本和历史分离，历史不再截断为最近 64 条；新版本通过重新读取首页发现，旧版本资格或撤销状态按读取时事实返回。秘密不在版本响应内，原资格核验、轮换与维护动作保持独立。

租户及 provisioning 管理目录使用 `filter/sort/fields/limit/cursor`；只有安装管理 realm 的权限可读取，不接受业务租户权限替代。
