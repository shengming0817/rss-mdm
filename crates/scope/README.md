# rss-mdm-scope

N03 / #2381 的纯集合核心。`resolve(&ScopeInput)` 只接受调用方已经解析的来源，不查询 Group、设备 API 或数据库。

## 输入与解释

`DeviceId` 与 `GroupId` 是独立角色类型，不能互传；两者包含 canonical `TenantId` 与 1–128 字节的 ASCII 字母、数字、`.`、`_`、`-` 标识。
`SourceRef` 包含 `SourceId::Direct(DeviceId)` / `Group(GroupId)`、非零来源版本与显式 `Timepoint`。
同一对象/来源种类/版本的成员必须一致；解析时间是解释依据，不允许据此改变同版本内容。
Direct 来源必须恰好包含自己的对象；Group 来源允许完整空集合。

`Limitations::Unrestricted` 表示未配置限制；`Restricted([])` 或全空限制来源表示配置为空。
结果为 Target 并集与 Limitation 并集的交集减 Exclusion 并集；未配置限制时不做交集。
所有来源先通过完整性、tenant 和内容冲突检查，失败整体返回错误，绝不返回部分结果。

输出 `target_sources`、`limitation_sources`、`exclusion_sources` 保留所有参与来源，包含空目标组与未命中排除。
输出成员和全部 Target 候选的解释均按对象/来源稳定排序去重；解释保存命中来源及限制未命中、
显式排除原因。`limitation_sources` 保留实际考虑的限制来源，即使没有匹配；None 与 Some([]) 分开。
相同成员来自多个输入来源时保留全部出处；同一来源的完全重复输入折叠。
来源 tenant 不匹配返回 `SourceTenantMismatch { source_ref, expected }`；成员 tenant 不匹配返回
`MemberTenantMismatch { source_ref, member, expected }`，三类输入来源均保留失败位置。
其余来源错误同样携带可定位来源；Display 只输出稳定分类，不输出身份值或底层任意错误正文。

调用方拥有来源认证、授权、版本真实性、Scope 定义/成员快照存储及历史解释持久化。
核心的 tenant 一致性检查不是认证证明；输入来源存在也不证明其内容可信。

## 验证与来源

`cargo test --locked -p rss-mdm-scope` 运行集合真值表、解释、排列不变性和失败输入测试。
`hack/core_consumer.py` 从固定产品 Git SHA 复用 `tests/model.rs`，直接消费本产品包及 canonical `TenantId` / `Timepoint` owner，
在仓外分别验证默认与关闭默认 features 的独立 lock、root 精确普通依赖集合、产品包普通/构建依赖闭包和实际行为；结果归本地 CI artifact。

- Rust 1.90.0 [`BTreeSet`](https://github.com/rust-lang/rust/blob/1.90.0/library/alloc/src/collections/btree/set.rs)：有序集合复用来源。
- WinMDM 历史 `src/internal/domain/policy/scope_resolver.go`：仅作为公式、直接目标与组展开去重证据；
  来源恢复见 [reference/README](../../reference/README.md)。不继承现场仓储查询、输入保序或缺失 tenant 检查。
