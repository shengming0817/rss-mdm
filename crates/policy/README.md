# rss-mdm-policy

策略生命周期与逐设备意图决策。公共契约由 [源码与 rustdoc](src/lib.rs) 持有，使用流程见 [任务指南](../../docs/guides/groups-scopes-policies.md)。

- kube-rs 1.1.0 [`controller::Action`](https://github.com/kube-rs/kube/blob/1.1.0/kube-runtime/src/controller/mod.rs)：参考决策结果与驱动执行分离；不引入 kube controller/runtime。
- WinMDM 历史 `src/internal/domain/policy/{value_object,entity}.go`：生命周期及事实语义证据；
