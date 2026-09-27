# rss-mdm-policy-postgres

新统一 Policy 的唯一持久 owner：`mdm_policy.policies`、不可变 `versions`、显式 `triggers` 和请求 `requests`。没有旧 aggregates、facts、Candidate、current Plan 或已保存执行意图表。

`PolicyStore` 绑定精确的 RSS 消息 runtime 和 tenant。`publish_in` 在借用事务中重新验证纯核心 CAS/版本决策并保存不可变内容；`replay_in` / `receipt_in` 支持同一请求恢复；`trigger_in` 只接受当前有效执行型版本，不推进编辑 CAS。所有 `*_in` 方法借用调用方事务，不自行结算，也不替调用者处理未知提交。`new` 与 `get` 则通过绑定 runtime 启动并结算准入/只读事务。

`read_in` 和 `version_in` 是供组合根使用的租户事务读取合同；修改依赖其结果的消费者须先取得自己的 owner 锁。只读消费角色仅取得精确 SELECT 权限，不能编辑策略。表的关系键及定义列同时是组合根的受版本约束 SQL 读取合同，用于跨 Scope/Execution 筛选；启动时的 catalog 与最小权限守卫验证合同。

冻结内容是宿主提供的 opaque JSON，adapter 不解释 Resource、Group/Scope、Agent 或 MDM 协议，不读取其它 owner 私表。Group/Scope 来源坐标与输入水位属于 `mdm_planning.source_heads`。宿主持有权限、内容核验、审计、引用竞争和后台唤醒；执行 owner 持有真实设备事实。

无旧部署，直接使用新的初始化 schema，不保留旧格式、检测或迁移路径。独立真实 PostgreSQL 验证包括 CAS 竞争、借用回滚、租户/runtime 隔离、不可变版本和丢失提交确认后的原身份恢复。
