# rss-mdm-policy-postgres

Policy 的持久 owner：一个聚合 revision、有界执行事实、不可变候选、引用令牌与显式计划指针。
不解析 Scope，不授权或派发设备执行。

候选按 `begin_candidate_in` → `append_candidate_targets_in` → `seal_candidate_targets_in` →
`advance_candidate_facts_in` 准备。目标页最多 1,000 台、当前目标总量最多 1,000,000；
执行历史按版本和设备身份排序分页，不按当前设备容量截断。候选身份使用唯一规范流式摘要，
分页边界不参与摘要。历史目标与意图从独立有界读取接口消费。

`save_candidate_in` 只重新校验策略 CAS 与规范化引用，安装完整候选指针及回执、事件。
保存不会写 `Planned` 或其它执行事实。`Command::RecordExecutions` 单独接受调用方确认的
真实执行受理/进度；授权属于宿主。旧 SelectTargets、Replan、整份计划/目标快照读写及解码已删除。

`EXECUTION_ADMISSION_MIGRATION_SQL` 安装独立 `mdm_policy_projection` 只读接缝。
`execution_admission(policy,candidate,revision,saved)` 只判断当前 tenant 的策略 CAS、候选安装
和引用令牌是否仍有效；宿主组合 Scope/身份依据后授予产品运行角色窄入口权限。
此投影不开放 Policy 私表，也不改变 `mdm_policy` 存储 schema 的函数禁入约束。

宿主提供同一 `Arc<PgRuntime>`，拥有权限、RSS claim 和关闭流程。`*_in` 校验 runtime owner
与 tenant，返回两层结果；业务拒绝必须处理，PG 错误传播给外层回滚。提交未知沿原身份读取或
精确重放；不制造新身份。启动校验精确 catalog、RLS、最低权限与迁移指纹。

```sh
cargo test --locked -p rss-mdm-policy-postgres
make t2-backend
# 提交后运行固定 SHA 独立消费者
make backend-consumers
```

参考 SQLx v0.9.0 `sqlx-core/src/transaction.rs` 的提交/回滚不确定语义，复用 RSS 公开事务和
Outbox，不引入通用任务或存储框架。T1/T2 不代表产品端侧 T3。
