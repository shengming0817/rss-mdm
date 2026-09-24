# rss-mdm-scope

目标、限制与排除的来源集合决策。公共契约由 [源码与 rustdoc](src/lib.rs) 持有，使用流程见 [任务指南](../../docs/guides/groups-scopes-policies.md)。

- Rust 1.90.0 [`BTreeSet`](https://github.com/rust-lang/rust/blob/1.90.0/library/alloc/src/collections/btree/set.rs)：有序集合复用来源。
- WinMDM 历史 `src/internal/domain/policy/scope_resolver.go`：仅作为公式、直接目标与组展开去重证据；
