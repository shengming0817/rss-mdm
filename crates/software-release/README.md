# rss-mdm-software-release

N08 / #2386 的独立软件发布决策核心。调用方提供候选、验证、主体声明和外部结果，
核心返回新快照、请求回执与决策；不访问数据库、软件源、系统时钟或终端。
N11 / #2389 负责 Resource、WinGet/Brew 映射、持久化、外部提交与对账；N12 负责真实管理身份、权限及审计。

## 输入和唯一转换入口

`Candidate::new` 创建候选，`Candidate::transition(Request, previous_receipt)` 是唯一业务转换入口。
`Snapshot`、`RingState` 和证据记录是可读取和重建的存储输入，`Candidate::restore` 校验租户、引用、时间、状态与证据后才接纳聚合。
这些输入不定义持久 wire 格式，也不证明存储真实性；schema 与生产迁移归 N11。

直接使用 `rss-request-context::TenantId`、`rss-contract::Timepoint`，本包不 re-export。
`CandidateId`、`RequestId`、`ActorId` 分角色且包含 tenant。身份值、软件身份各项和 artifact key 为 1–128 字节，
只允许 ASCII 字母、数字及 `._-/+@`，拒绝空路径段与 `.` / `..` 段；它们是内部引用，不接受 URL、凭据或任意正文。
`SoftwareIdentity::new` 接收具名 `SoftwareIdentityFields`：source、package、version、platform，
由组装映射精确身份；验证后的值通过 `fields()` 只读访问。
一个 Candidate 是完整平台包版本。`Content` 接收描述、源配置快照、完整 manifest 和 1–64 个 `VariantContent`；每项包含 architecture、variant 和具名产物。总计最多 256 个产物引用，排序后编码；同一产物 key 跨 variant 共享时摘要必须一致。
多架构/依赖闭包由调用方完整声明，不由核心发现、下载或执行。

## 审批与状态

候选只保存一份内容及其生效时间 `content_at`、CAS revision、整体 Disposition 和三个固定环记录。
调用方通过 `Snapshot::ring_state(Ring)` 读取环记录，无需维护数组索引映射。
RingState 将必要证据放进对应枚举分支；`is_published()` 仅在后端报告 Applied 时成立。
整体隔离/弃用与外部发布事实分别保留，不能用一个 status 字段相互覆盖。

| 操作 | 前置与结果 |
| --- | --- |
| Validate | 验证时间不能早于当前内容生效；后环还要求前环已确认发布，且验证时间不能早于前环成功。Passed 进入 Validated；Failed/Unknown 清除有效审批并回到 Candidate。完全相同的验证保留批准。 |
| Approve | 当前环验证通过；绑定发布者、审批者、分离策略和前环发布身份。默认 Separate；只有显式 AllowSameActor 才允许自审。 |
| Authorize | 请求主体等于批准的发布者，审批指纹精确匹配。首次返回 Publish；已有 Pending/Unknown 返回 Reconcile；已有 Applied 返回 Updated。 |
| Replace | 软件身份不能变化。首次授权前内容变化清空验证/审批；任一环已有发布尝试后冻结，包括确认失败的尝试。完全相同内容只确认原内容。 |
| Quarantine / Deprecate | 关闭该候选所有环的新授权、重试、验证和审批；本期无解除和相互转换，同一关闭操作可重复确认。 |

Test → Pilot → Production 严格顺序，每环重新验证和审批，内容不变。
审批绑定候选身份、内容指纹、环、验证者、证据摘要/时间、发布者、审批者、分离策略、审批时间及前环发布身份。
核心不规定证据 TTL、审批人数或认证权威；Passed 是可信调用方声明，不能直接从未验证用户输入映射。
请求和证据时间使用显式 UTC 秒 Timepoint；新转换时间不倒退，证据不得来自未来或早于其证明的内容/授权/前环事实。
创建和实际替换内容设置 `content_at`，相同内容不更新时间；restore 同样核对该时间与全部验证链。

## 幂等和外部恢复

`Transition::Applied` 返回 next、receipt、decision。调用方须在受控事务内校验 revision、
持久化 next 与 receipt 并完成必要成功审计，提交后才驱动外部操作。expected_revision 不证明跨进程 CAS。

幂等键为 tenant + request，receipt 另外绑定 candidate、请求指纹及前后 revision。
N11 必须查询持久唯一记录，只在确定不存在时传 None；读取失败不能视为不存在。
重放保留原 actor、expected_revision、as_of 和操作，变化返回 RequestConflict。
`Replayed` 只返回历史 receipt，不带 next 或 Publish，不回滚状态、不重发指令、不解除撤回。
核心不保存无界请求日志；跨候选的请求唯一性和同软件版本内容唯一性由 N11 持久保护。

PublicationId 从审批指纹规范派生，不依赖请求、重试次数或重试时钟。尝试保留原审批、attempt、authorized_at 和结果。
`PublicationOutcome` 区分 Pending 与 Reported；`Record` 只接收 `PublicationResult`，不能报告 Pending：

- Pending：已决定发布，不证明外部调用是否开始；恢复或换请求后只对账。
- Unknown：保留原身份并返回 Reconcile，不转为失败或成功。
- NotApplied：调用方确认该尝试未生效且以后不会再生效，才允许显式 Retry，沿用 PublicationId、递增 attempt。
- Applied：调用方确认外部内容符合原批准；终态只接受完全相同的重复结果，矛盾结果拒绝。

暂时查询不到结果不能证明 NotApplied；N11 必须处理仍在执行的旧调用和后端一致性。
Record 的 ring、PublicationId、attempt 须匹配当前尝试；PublicationId 间接绑定 tenant、候选、内容及审批。
N11 必须核对真实 backend 目标、元数据和产物摘要，再构造结果；参数匹配不证明后端事实。
旧 attempt 不能覆盖新尝试；Retry 取代前次 NotApplied 后，前次历史由 N11 持久记录保留。

隔离/弃用后仍允许 Record：迟到 Applied 补充外部暴露事实，整体状态不变，不返回新授权。
N11 app 负责真实源下架和快照保留；私有下载授权、缓存窗口及终端卸载/降级归后续产品流程。
重新发布须创建新候选并重新审批；N11 仍须核对同版本字节不可替换及旧未知发布没有竞争写入。

## 编码和验证

公共类型、字段与转换契约也在 item rustdoc 中提供；`cargo doc --no-deps -p rss-mdm-software-release` 可生成入口。
crate 启用 `missing_docs`，本地 CI 的 Clippy `-D warnings` 阻止新增未文档化公共项。

content、approval、publication、request 使用 `rss-mdm-software-release/<kind>/v2` 域。
变长字节前缀为 big-endian u64 长度，计数/枚举/秒时间为 big-endian u64，tenant 为 canonical 16 字节，
摘要为原始 32 字节；variant 按 architecture/variant 排序，其产物按 key 排序。字段与枚举标签唯一由编码源码持有，固定向量和逐字段变化测试验证。
无旧 API、历史模型 alias、兼容 facade、序列化双路径或 feature 开关。

```sh
cargo test --locked -p rss-mdm-software-release
python3 -O -m unittest discover -s tests -p 'test_ci.py'
# 提交全部输入并保持 clean 后执行固定 SHA 消费
python3 hack/core_consumer.py
# 完整本地入口，提供既有固定 Identity 候选和真实依赖
MDM_IDENTITY_CANDIDATE=/absolute/approved-candidate make ci
```

同一 tests/model.rs、tests/version.rs 在仓内和仓外 consumer 运行。每个 consumer 显式声明唯一产品包及 canonical 两个值类型 owner，
使用独立 workspace/配置/lock/target，验证默认/关闭默认 features、精确 Git 身份和普通/构建依赖闭包。
从产品核心自身遍历闭包，防止 consumer 补齐缺失声明；canonical 值类型 owner 的 features 必须为空。
本地 CI 记录受测 SHA、RSS revision、lock 摘要、features、命令和结果。
本项新增 T1；N11 实际发布 T2、终端 T3 和 registry 发布不在该证明范围。

## 来源

- [Tough Target](https://github.com/awslabs/tough/blob/98d8eb8b2ce63515d9b4981c938ef6453c5b5771/tough/src/schema/mod.rs#L432-L500)：精确产物摘要；借鉴内容绑定，不引入 TUF 网络/验签协议。
- [in-toto Step](https://github.com/in-toto/in-toto-rs/blob/48e57fd04624d30d081fae1dddf56caaa4a5b81e/src/models/layout/step.rs#L92-L110)：证据与参与者约束一起绑定；真实身份和验证由产品 owner 提供。
- 历史 WinMDM `src/internal/domain/resource/{entity,value_object}.go` 和 `src/internal/application/resource/service.go` 仅作缺口证据，不继承无 tenant、可变版本 detail 或系统时钟。来源与恢复见 [reference/README](../../reference/README.md)。

#2389 直接替换原单 variant 内容模型，不提供 V1 发布身份兼容路径；PG 持久化只接收当前模型。完整平台版本与一次 WinGet manifest / Brew document 发布一一对应，避免分架构审批造成未批准内容发布或撤回误删。
