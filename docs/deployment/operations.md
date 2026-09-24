# 运维与恢复

## 版本切换

允许升级的旧基线为 `a83f7876289f15f294940964df69579d62126557` 的固定 name+SHA-256 ledger，或安装器明确接受的 Apple 基线。空库可安装，当前完整 ledger 可重放；其他前缀、缺失、未知、修改摘要、未完成单元均拒绝。基线清单固定在 `crates/app/src/migration/baseline-a83f7876.json`。历史 SQL 不改写。

1. 在旧版本正常运行时排空 Agent 待投递报告，撤销旧 Agent registration 及 credential。Agent 能力声明遵循 [协议包](../../crates/agent-wire/README.md)。
2. 检查旧 Script 版本。旧声明不含完整执行接口，安装器拒绝推断默认值或迁移它；必须显式重新建模和规划数据迁移，不能删除历史记录来绕过检查。
3. 从前 Apple 基线升级时，还须排空旧非终态命令、未发布 Outbox、有效 Windows 会话、未封存或未投递采集与旧 reconcile 工作及租约；两组前置检查均通过后才安装新单元。停止旧服务，备份数据库和本地制品，使用受控 owner 执行 migrate。新增的 nullable `mdm_commands.action_plans.blocked_at` 保存容量阻塞的原 occurrence 坐标；升级不从 `scan_at` 推断或回填它。预检遍历全部已安装租户，RLS 不会隐藏未清理状态。
4. 部署新服务和可信签名配置，通过新的 Enrollment 授权重新注册 Agent。每个 tenant 制品目录必须允许服务创建并锁定 `.upload.lock`；启动会在持有该跨实例独占锁时删除精确命名的 `.upload-<canonical hyphenated UUID>` 残留普通文件，失败则以 CommandStorage 阻止启动。旧凭据即使数据库状态误留 active，也不能用于 V2；不保留候选兼容解码，也没有 V1 路由或双协议降级。
5. Inventory 使用 inventory-v3 从原 Observation journal 重放。原事实、历史和基础报告保留，重放完成前不把视图完整性当作已确认。

数据库版本、服务代码和 Agent wire 必须整体切换。失败前置检查不会删除账本、自动撤销身份或清空业务证据。完成迁移后的回退使用成套数据库/制品备份和对应旧服务，不能仅降级二进制。

管理客户端同时切换 Enrollment 整组 `/api/v3`、Commands 整组 `/api/v2`（含计划执行）。内部 dispatch 使用 `mdm.command-dispatch/v2`、route `device.command`，消息/reconcile 域为 `mdm.commands.v2`；旧消息只作历史，不被新 decoder 消费。候选已绑定对应 UI，其它外部 API 消费者须在同一停写窗口升级，不存在旧路由别名、双写或双协议降级。


## 就绪、停机与恢复

/livez 表示进程可响应。/readyz 要求启动 admission、首次有界恢复与投影通过，工作任务仍运行且尚未停机；不表示 backlog 已全部追平，健康查询不额外探测 IdP。

SIGINT/SIGTERM 先停止接入并排空，再取消和 join 工作任务，最后关闭存储及认证 KDF/runtime，整体关闭预算 40 秒。关键任务异常或关闭失败返回非零；进程重启由部署 owner 决定。被动查询不延长认证 idle，组件事务使用自身预算完成，宿主不以请求 timeout 丢弃其提交结果。

监控 mdm_inventory_progress、mdm_management_retention_failure、mdm_shutdown_failure、mdm_maintenance_shutdown_failure 和 audit_failure；日志记录闭合类别与操作坐标，不打印凭据或协议正文。提交未知按原操作查询恢复，不更换幂等键或删除 ledger。

命令闭环另监控 `mdm_command_relay_failure` 与 `mdm_command_recovery_failure`：

| 条件 | 阈值与处置 |
|---|---|
| relay `transient` 或 recovery `Transient` / `Deadline` | 同一 messageId/target 持续 5 分钟告警；检查 PostgreSQL 可达性、Retry 时间和租约持有者，保持原消息与幂等键 |
| `commit_unknown` / `CommitUnknown` | 首次出现即告警；按原 operationId 查询并精确重放，不能换 ID、清 Outbox 或当作回滚 |
| `invariant` / `Invariant`、`StorageContract`、`Permanent`，尤其 `phase=runner` | 立即告警；关键 worker 退出由统一运行时关闭服务。核对候选、迁移账本、角色/ACL/RLS 与固定 catalog，修复根因后重启同一身份的服务 |

relay 的完整 messageId 保留类型前缀：`dispatch.<UUID>` 关联同 UUID 的 operation，`action.<UUID>` 关联企业任务 run；recovery 的 `target` 是设备文本 ID 的 SHA-256 scope，结合 `mdm_commands.devices` 定位。使用有设备读取权限的管理查询查看 command、最新 attempt 和 CollectionRun。`phase` 区分 claim、accept、settle 与 runner/scan；日志不携带预期值、原生正文或浏览器凭据。恢复后确认告警停止、同一 command 可继续收敛；终态任务不得因重启复活。候选契约可用 `make command-catalog` 离线校验，生产修复是否满足契约仍由启动/事务准入判断，禁止导出漂移生产结构覆盖固定 JSON。

安装失败保持服务停止并保留证据。回退指停止新部署后恢复原有独立部署及其一致数据库/密钥备份；新代码没有中央认证回退路径。仅在新候选和 smoke 通过后，按精确镜像身份、归档目录和专属缓存记录清理本任务废弃产物，不进行全局 prune。



## 迁移失败

迁移单元与 ledger intent 保留中断证据。SQL 或完成确认不确定时，先检查数据库与不可变 SQL，不把 complete=false 当作盲目重跑 DDL 的授权。拒绝基线或摘要不匹配时保留数据；不删除账本、自动清库或改写历史摘要。运行角色无 DDL，启动检查 schema、权限和 RLS；修复漂移不能从生产库覆盖固定 catalog。

当前准确迁移集合由二进制 --describe 与 [迁移源码](../../crates/app/src/migration.rs) 持有。升级须停旧写入口；回退恢复匹配数据库、制品、密钥与旧服务，不能仅降级二进制。数据库角色与首次安装见 [安装指南](installation.md)。Apple 证书、APNs 与 CA 排障见 [Apple 管理](../guides/apple-management.md)。
