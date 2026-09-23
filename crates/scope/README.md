# rss-mdm-scope

Scope 的纯决策核心。唯一计算入口 `resolve_device(&DeviceInput)` 接受一个设备及有界来源成员证据，不查询 Group、设备 API 或数据库，也不接受完整设备集合。

## 输入与解释

公共输入直接使用 `rss-request-context::TenantId` 和 `rss-contract::Timepoint`；本包不重导出它们。
`DeviceId` 与 `GroupId` 是独立角色类型，包含 canonical TenantId，不能互传。
`SourceRef` 包含来源身份、非零版本与解析时间；时间是来源证据，不决定过期。

每个来源使用 `Membership::Known(bool)` 表达已确认的成员关系；`Incomplete` 与 `Failed`
分别拒绝不完整来源和解析失败，不能伪装成确定的非成员。直接设备来源必须与正在判断的
设备一致；相同来源身份和版本的证据不能相互矛盾。所有来源都验证，包括未命中来源。

`limitations: None` 表示未配置限制，`Some([])` 表示配置为空。结果为目标来源并集与
限制来源并集的交集减排除来源并集。没有命中目标时返回 None；命中目标时返回该设备的
来源解释及排除原因。每个设备最多 1,000 个不同来源、3,000 个角色项。

调用方从已完成的不可变来源枚举设备，保存完整来源定义、未命中来源及成员结果，
并在全部分页完成后发布。核心只产生当前设备的决策，不将局部页当作完整集合。
来源认证、授权、版本真实性、存储及恢复由调用方负责；tenant 检查不能代替认证。

旧 `resolve`、`ScopeInput`、全量 `Resolution` 和 `ScopeResolution` 已移除，
compile-fail 测试保护退出约束，不提供兼容包装。

## 验证与来源

`cargo test --locked -p rss-mdm-scope` 运行集合真值表、解释、排列不变性和失败输入测试。
`hack/core_consumer.py` 从固定产品 Git SHA 复用 `tests/model.rs`，直接消费本产品包及 canonical `TenantId` / `Timepoint` owner，
在仓外分别验证默认与关闭默认 features 的独立 lock、root 精确普通依赖集合、产品包普通/构建依赖闭包和实际行为；结果归本地 CI artifact。

- Rust 1.90.0 [`BTreeSet`](https://github.com/rust-lang/rust/blob/1.90.0/library/alloc/src/collections/btree/set.rs)：有序集合复用来源。
- WinMDM 历史 `src/internal/domain/policy/scope_resolver.go`：仅作为公式、直接目标与组展开去重证据；
  来源恢复见 [reference/README](../../reference/README.md)。不继承现场仓储查询、输入保序或缺失 tenant 检查。
