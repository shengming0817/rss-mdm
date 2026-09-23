# rss-mdm-policy

N04 / #2382 的纯策略版本、生命周期与计划差分核心。无 Scope/Group/Resource、PG、HTTP 或设备通道依赖。
载荷是调用方解析的不可变引用与 SHA-256 摘要，不是下载 URL、凭据或平台指令。
公共 ID 分为 PolicyId、PayloadId、DeviceId、TargetSnapshotId、RequestId，不提供通用 ObjectKey 或跨角色转换。
Scope 到 Policy 的设备身份由 N12 在明确映射点按 canonical tenant 和值重新构造。

## 生命周期和快照

公共输入直接使用 `rss-request-context::TenantId` 和 `rss-contract::Timepoint`；本包不重导出它们。
调用方须从各自 owner 导入，compile-fail 文档测试保护该边界。

`Policy::draft` 创建 revision 0；`transition(expected_revision, operation)` 返回新快照：
Draft → Active ↔ Paused；Active/Paused → Archived；归档终态。
Activate 可选择更高版本并进入 Active，Resume 只恢复原版本。
同版本改内容、版本回退、revision 不匹配及 revision 溢出均拒绝。

`Version` 的 policy、非零版本号、载荷与移除规则创建后不可修改；载荷对象/非零 revision 标识内容，
相同载荷身份不能对应不同摘要。`restore` 供可信存储读取使用，只验证结构，不证明数据库内容真实性。
同一输入中所有历史版本也须满足不可变约束；跨请求的不可变存储和 revision CAS 归 N10。

核心仅接受逐设备成员关系与逐执行事实，调用方从完成的不可变来源分页提供输入。
`desired_for_device` 使用历史存在性摘要决定 Add/Supersede；`classify_record` 决定 Retain/Cancel。
不可变版本、重复事实及跨记录冲突由持久 owner 校验，核心验证当前记录的租户、策略、版本和载荷。
DeviceId 保留 1–256 UTF-8 字节、不含控制字符的产品身份；其它角色键为 1–128 字节 ASCII。
所有错误使用封闭类别，不输出资产值。

## 差分与事实

| 场景 | 计划行为 |
| --- | --- |
| Active 目标无历史执行 | Add，产生稳定 Apply 执行键 |
| 同版本已有任意进度的执行 | Retain，保持身份和原始事实；失败/取消不隐式重试 |
| 新版本目标有旧版本执行 | Supersede 关联旧键；旧非终态另产生 Cancel(Superseded) |
| Paused | 不新增、不推进 Apply；范围内同版本记录 Retain(Paused)，旧版本非终态仍 Cancel(Superseded)；恢复沿用原键 |
| 范围退出 | 非终态 Cancel(ScopeExit)，终态保留历史；暂停期间也处理明确范围退出 |
| Archived | 非终态 Cancel(Archived)，终态保留历史，无新增 Apply |

`Progress` 分 Planned、Running、Unknown、Succeeded、Failed、Cancelled；`Effect` 独立分
Unverified、Unknown、VerifiedPresent、VerifiedAbsent。成功不证明已核实，取消不证明撤销。
取消意图引用原记录，不改写真实进度或效果。未知事实不能自动转为成功、已取消或可重试。

Active 状态仅是 Apply 调度的策略前置条件，不是授权、任务领取权或任意 Retain 项可重放的许可。
Cancel 意图仍需持久化和后续执行 owner 处理；核心不驱动或撤销任何外部操作。
同版本取消后重入仍 Retain(Cancelled)，不会生成新执行；显式重试需要后续独立契约。
唯一已实现移除规则是显式 `CancelOutstandingRetainEffects`，不推导 cleanup、卸载、补偿或回滚。

## 身份和原子应用边界

执行键是结构化 `(tenant, policy, version, device, Apply)`，不包含 request、时间或目标快照 revision。
`PlanId` 是规范决策输入的 SHA-256；不同事实或前置条件可得到新计划，但不产生不同的同版本执行身份。
唯一编码在 `src/fingerprint.rs`：目标与执行分别规范化流式折叠，再通过
`rss-mdm-policy/plan/v2` 绑定策略和来源版本。整数使用 big-endian u64，变长字节使用长度前缀，
tenant 为 canonical 16 字节；禁止使用 Debug/内存布局。折叠状态与计数可以随持久游标恢复，
分页大小不改变结果。request 与时间只作来源证据，不进入摘要。

持久 owner 在完整输入封闭后计算摘要，保存时校验全部版本并安装候选指针。
保存意图不是执行事实，也不是执行批准。旧全量 PlanInput/TargetSnapshot/reconcile 和 V1 编码均已删除。

## 验证与来源

`cargo test --locked -p rss-mdm-policy` 覆盖生命周期矩阵、逐记录版本与载荷校验、
所有进度/效果组合、暂停/退出/归档、流式摘要的分页与重启稳定性，以及旧入口不可用。
`hack/core_consumer.py` 在仓外固定 Git SHA 分别验证默认与关闭默认 features 的消费者。
存储 owner 的集成测试另外覆盖跨记录身份冲突、完整性、幂等与提交未知。

- kube-rs 1.1.0 [`controller::Action`](https://github.com/kube-rs/kube/blob/1.1.0/kube-runtime/src/controller/mod.rs)：参考决策结果与驱动执行分离；不引入 kube controller/runtime。
- WinMDM 历史 `src/internal/domain/policy/{value_object,entity}.go`：生命周期及事实语义证据；
  恢复见 [reference/README](../../reference/README.md)。不继承随机 execution UUID、仓储查询、通道展开或旧兼容模型。
