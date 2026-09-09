# rss-mdm-policy

N04 / #2382 的纯策略版本、生命周期与计划差分核心。无 Scope/Group/Resource、PG、HTTP 或设备通道依赖。
载荷是调用方解析的不可变引用与 SHA-256 摘要，不是下载 URL、凭据或平台指令。

## 生命周期和快照

`Policy::draft` 创建 revision 0；`transition(expected_revision, operation)` 返回新快照：
Draft → Active ↔ Paused；Active/Paused → Archived；归档终态。
Activate 可选择更高版本并进入 Active，Resume 只恢复原版本。
同版本改内容、版本回退、revision 不匹配及 revision 溢出均拒绝。

`Version` 的 policy、非零版本号、载荷与移除规则创建后不可修改；载荷对象/非零 revision 标识内容，
相同载荷身份不能对应不同摘要。`restore` 供可信存储读取使用，只验证结构，不证明数据库内容真实性。
同一输入中所有历史版本也须满足不可变约束；跨请求的不可变存储和 revision CAS 归 N10。

`TargetSnapshot` 必须完整，否则 `reconcile` 拒绝；同 tenant 的设备键排序去重。
现阶段键为 1–128 字节 ASCII 字母、数字、`.`、`_`、`-`，不接受 URL。
已有执行输入是每个执行的当前事实快照，完全重复允许，互相矛盾拒绝；历史事件归并由调用方拥有。
未来版本事实、其他策略事实及混租户输入整体拒绝，范围退出设备的事实则是合法输入。

## 差分与事实

| 场景 | 计划行为 |
| --- | --- |
| Active 目标无历史执行 | Add，产生稳定 Apply 执行键 |
| 同版本已有任意进度的执行 | Retain，保持身份和原始事实；失败/取消不隐式重试 |
| 新版本目标有旧版本执行 | Supersede 关联旧键；旧非终态另产生 Cancel(Superseded) |
| Paused | 不新增、不推进 Apply，范围内记录 Retain(Paused)；恢复沿用原键 |
| 范围退出 | 非终态 Cancel(ScopeExit)，终态保留历史；暂停期间也处理明确范围退出 |
| Archived | 非终态 Cancel(Archived)，终态保留历史，无新增 Apply |

`Progress` 分 Planned、Running、Unknown、Succeeded、Failed、Cancelled；`Effect` 独立分
Unverified、Unknown、VerifiedPresent、VerifiedAbsent。成功不证明已核实，取消不证明撤销。
取消意图引用原记录，不改写真实进度或效果。未知事实不能自动转为成功、已取消或可重试。

`scheduling_open` 仅是 Apply 调度的策略前置条件，不是授权、任务领取权或任意 Retain 项可重放的许可。
Cancel 意图仍需持久化和后续执行 owner 处理；核心不驱动或撤销任何外部操作。
同版本取消后重入仍 Retain(Cancelled)，不会生成新执行；显式重试需要后续独立契约。
唯一已实现移除规则是显式 `CancelOutstandingRetainEffects`，不推导 cleanup、卸载、补偿或回滚。

## 身份和原子应用边界

执行键是结构化 `(tenant, policy, version, device, Apply)`，不包含 request、时间或目标快照 revision。
`PlanId` 是规范决策输入的 SHA-256；不同事实或前置条件可得到新计划，但不产生不同的同版本执行身份。
V1 编码在 `src/fingerprint.rs`：域 `rss-mdm-policy/plan/v1`，整数为 big-endian u64，变长字节前缀为 u64 长度，
tenant 为 canonical 16 字节，摘要为固定 32 字节；版本、目标和事实按封闭字段及有序集合编码，禁止使用 Debug/内存布局。
request 与 `as_of` 仅作显式溯源，不参与此版本的决策或身份。算法不读系统时钟。

Plan 返回策略 revision、目标快照身份/revision 和确定的意图。N10/N12 必须在应用前确认这些输入仍有效，
并在同一事务持久化计划、执行键唯一性与事件；不能只存 PlanId 或依赖纯核心实现跨进程互斥。
调用方拥有可信设备映射、认证授权、事实完整性和持久化；私有字段不证明外部事实可信。

## 验证与来源

`cargo test --locked -p rss-mdm-policy` 覆盖状态转换矩阵、版本/载荷冲突、稳定身份、重算/重入、
暂停/恢复/退出/归档、旧事实和取消/效果分离。`hack/core_consumer.py` 复用公共 API 测试，在仓外以固定 Git SHA
分别验证默认与关闭默认 features 的独立 consumer；独立消费结果不是 registry 发布或端侧 T3 证明。

- kube-rs 1.1.0 [`controller::Action`](https://github.com/kube-rs/kube/blob/1.1.0/kube-runtime/src/controller/mod.rs)：参考决策结果与驱动执行分离；不引入 kube controller/runtime。
- WinMDM 历史 `src/internal/domain/policy/{value_object,entity}.go`：生命周期及事实语义证据；
  恢复见 [reference/README](../../reference/README.md)。不继承随机 execution UUID、仓储查询、通道展开或旧兼容模型。
