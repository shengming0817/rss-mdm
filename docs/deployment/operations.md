# 运维与恢复

## 版本切换

当前版本只支持空库安装，以及完全一致的当前安装记录重放。旧版本、前缀、缺失、未知、摘要修改或未完成的迁移记录均拒绝；不提供旧审计表导入或兼容迁移。拒绝时保留数据库及安装记录，不自动清库或重写摘要。

部署使用配套数据库、服务、Agent 协议及可信签名配置。管理客户端使用 Enrollment `/api/v3`、Commands `/api/v2`。安装前显式配置审计 Plain 或 Ledger；Ledger 的 key ID 与受保护密钥文件必须由部署方提供，缺失或错误时拒绝启动。

每个 tenant 制品目录必须允许服务创建并锁定 `.upload.lock`；启动持有跨实例独占锁时清理精确命名的 `.upload-<canonical hyphenated UUID>` 残留普通文件，失败则阻止启动。回退使用配套数据库、制品、密钥备份和服务，不能仅降级二进制。

## 就绪、停机与恢复

/livez 表示进程可响应。/readyz 要求启动 admission、首次有界恢复与投影通过，工作任务仍运行且尚未停机；不表示 backlog 已全部追平，健康查询不额外探测 IdP。

SIGINT/SIGTERM 先停止接入并排空，再取消和 join 工作任务，最后关闭存储及认证 KDF/runtime，整体关闭预算 40 秒。关键任务异常或关闭失败返回非零；进程重启由部署 owner 决定。被动查询不延长认证 idle，组件事务使用自身预算完成，宿主不以请求 timeout 丢弃其提交结果。

审计恢复要求各产品运行连接使用 `READ COMMITTED`；启动与每次借用事务均检查，组件不替调用方修改隔离级别。业务事务先取得 Audit head，以及 Ledger 模式下固定审计链的 head，再取得业务和 Outbox 锁。提交未知后使用原操作身份和原请求重试，锁后的新语句快照同时核对业务回执、产品审计回执与组件记录；恢复原 canonical bytes 和 recorded_at，不生成新的事件身份。单边缺失、指纹或字节冲突均拒绝并要求修复，不能补造记录。两者都不存在也只有在成功取得同一锁、确认先前数据库事务已结束后才允许重新判定业务；这不证明设备或软件源的外部副作用回滚。锁或读取超时继续保留未知状态。注册替换、撤销与 Apple CheckOut 的事务预算为六秒，与 Commands 一致，覆盖同事务终结积压采集及逐事件审计；超时按实际结算状态处理，未确认结算不推断为回滚，不分批伪装成完整退役。

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

命令闭环另监控 `mdm_command_relay_failure` 与 `mdm_command_recovery_failure`：

| 条件 | 阈值与处置 |
|---|---|
| relay `transient` 或 recovery `Transient` / `Deadline` | 同一 messageId/target 持续 5 分钟告警；检查 PostgreSQL 可达性、Retry 时间和租约持有者，保持原消息与幂等键 |
| `commit_unknown` / `CommitUnknown` | 首次出现即告警；按原 operationId 查询并精确重放，不能换 ID、清 Outbox 或当作回滚 |
| `invariant` / `Invariant`、`StorageContract`、`Permanent`，尤其 `phase=runner` | 立即告警；关键 worker 退出由统一运行时关闭服务。核对候选、迁移账本、角色/ACL/RLS 与固定 catalog，修复根因后重启同一身份的服务 |

relay 的完整 messageId 保留类型前缀：`dispatch.<UUID>` 关联同 UUID 的 operation，`action.<UUID>` 关联企业任务 run；recovery 的 `target` 是设备文本 ID 的 SHA-256 scope，结合 `mdm_commands.devices` 定位。使用有设备读取权限的管理查询查看 command、最新 attempt 和 CollectionRun。`phase` 区分 claim、accept、settle 与 runner/scan；日志不携带预期值、原生正文或浏览器凭据。恢复后确认告警停止、同一 command 可继续收敛；终态任务不得因重启复活。候选契约可用 `make command-catalog` 离线校验，生产修复是否满足契约仍由启动/事务准入判断，禁止导出漂移生产结构覆盖固定 JSON。

安装失败保持服务停止并保留证据。回退指停止新部署后恢复原有独立部署及其一致数据库/密钥备份；新代码没有中央认证回退路径。仅在新候选和 smoke 通过后，按精确镜像身份、归档目录和专属缓存记录清理本任务废弃产物，不进行全局 prune。



## 接入与审计容量

配套网关对实际 TCP peer 的通用 `/api/` 请求执行每秒 10 次、burst 20 的 admission，登录仍使用
更严格的独立额度；转发头不能改写额度身份。宿主每个 HTTP envelope 最多接纳 32 个同时进行的
审计请求，健康检查及由 Identity 自有结算的路由不占此额度。超额在业务处理前返回 429
（Agent 使用既有 503 serviceUnavailable）及 Retry-After，不触发 handler 或持久审计。
已接纳请求的认证拒绝、查询及未知结果仍完整审计，不降采样、不降级 Plain，也不改变先取 Audit 锁的顺序。
Windows retention 每秒先做无行锁的只读候选检查；无过期会话时不取 Audit head。
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
