# 基于 RSS 的 Rust 产品重写

状态：工程方向确定，以下首期组合与拆分作为实施基线；具体接口、支持矩阵和生产参数随对应交付冻结。

目标 owner 为 [项目目标](../../product/project-goals.md)；源码复核见 [当前基线](../../reference/202609072231-003-rss-current-baseline.md)。

## F01 已定实现约束（#2346）

本项改用 Cargo.toml 固定的 RSS Git revision 和独立 Cargo.lock；只做本地 CI，不等待或宣称
candidate/registry 发布。一个 package/CLI 提供 migrate、ingest-fixture、project、inspect；
fixture 是可信本地输入，不代替设备认证。只投影固定 coverage 的设备型号与 OS 版本，
按完整流身份隔离资产，不加入跨来源解析。运行及恢复语义见
[F01 指南](../../guides/202609080000-2346-local-inventory.md)。

## 仓库与依赖边界

| 仓库 | 拥有 | 不拥有 |
| --- | --- | --- |
| RSS | 已接纳的公共契约、持久消息、命令、Observation、Projection、Reconcile、Saga、runtime 等组件及 provider | MDM 业务、设备认证、平台协议、产品配置与迁移执行 |
| rss-mdm | Device/Registration/Authority、CollectionRun、Inventory、Group/Criteria、EffectiveDevicePlan、Policy/Compliance、Artifact/Deployment、Access/Audit、原生会话与交付、服务端装配 | 第二套通用 Outbox/命令引擎、终端安装与更新实现 |
| rss-mdm-agent | Rust Agent 的本地 journal、采集、执行、结果恢复、Windows/macOS 适配、签名安装和更新 | 服务端策略权威、PG/broker adapter、另一份共享协议定义 |
| 现有前端仓 | 页面与交互；适配版本化管理 API | 产品状态与字段规则的独立实现 |

Agent wire schema/DTO 由 `rss-mdm` 中的独立协议包拥有，经版本化 artifact 向 Agent 发布；只含协议值类型与兼容约定，不传 Rust 内存对象，不引入服务端 domain、PG 或 RSS provider 闭包。两端可以使用不同 RSS 版本，线上协议兼容不等于 Cargo 版本相同。

通道中立的身份与报告模型先由产品定义；Agent 协议 producer PR 先产出版本化 artifact，Agent 公共 core/journal 的 consumer PR 锁定后，Windows 与 Mac 平台 adapter 才分别接入。Agent-only 与 Mac 原生注册均不依赖 Windows MDM 注册完成。

产品组合根 → 用例与产品/RSS adapter → 产品 domain / RSS capability core。domain 不依赖 HTTP/SQL/broker；RSS 不依赖产品。本批后端能力已由 #2379 确定独立 crate 边界，按下节契约在对应实现 PBI 创建有行为的包，不预建空包或全局依赖容器。

## 独立后端能力契约（N01 / #2379）

状态：契约与 package 名称已冻结；本节不声明实现、独立消费验证或 registry 发布完成。
本节唯一拥有契约与 package 身份；目录、PBI owner 和实施依赖见[路线](../../product/202609072231-002-rust-rewrite-roadmap.md#独立后端能力-n01n12)，证明方法见[消费规则](../../rules/rust-rss-dependencies.md#产品内部逐-crate-独立消费)。

### Package 身份与分层

沿用 `rss-mdm-<能力>`，核心不追加 `-core`，PG adapter 追加 `-postgres`；Rust 导入名将连字符替换为下划线。
核心为 `rss-mdm-group`、`rss-mdm-scope`、`rss-mdm-policy`、`rss-mdm-resource`、
`rss-mdm-winget-source`、`rss-mdm-brew-source`、`rss-mdm-software-release`；PG adapter 为
`rss-mdm-group-postgres`、`rss-mdm-policy-postgres`、`rss-mdm-resource-postgres`、`rss-mdm-software-release-postgres`。
当前 `publish = false` 与固定 Git revision 消费保持；名称不表示 registry 已占用。不建立旧名 alias、facade 或双路径。
不新增 scope-postgres、common/types 包或聚合 SDK，应用组装复用 #2343 的实际骨架，不另起独立库发布名。

七项能力相互无业务 Cargo 依赖，不在公共签名泄漏另一核心的业务类型；产品 composition 显式映射输入输出。
Group/Scope/Policy/Resource/发布核心不依赖 PG、HTTP、设备通道或应用装配；平台源只带自身必要协议/Git 接缝依赖。
PG adapter 只依赖对应核心与必要 RSS/PG，拥有专属 schema、原子持久化和恢复；不读取其他能力的业务表来绕过组合边界。
N11 组装拥有 Resource、发布与平台源之间的映射、外部提交及对账；N12 拥有资产到组/范围/计划的映射、管理 API、真实权限及审计。
产品 migrator 统一执行各 adapter 及应用业务表的迁移，通用事务消息与恢复机制复用 RSS，不另建 Outbox/UnitOfWork。

静态组定义、创建/编辑/删除用例、手工成员与版本唯一归 N09 的 `rss-mdm-group-postgres`，与动态组规则/成员共用组身份和专属 schema；N12 只通过该 owner 接入静态组 CRUD/批量成员管理，不另存一份组定义或成员。静态组不进入 Criteria 求值，集合差分可复用 Group 核心；动态重算不得覆盖静态成员，手工成员接口不得修改动态组的计算结果。
Scope 定义及版本、Target/Limitation/Exclusion 的直接对象/组引用、解析使用的成员版本/时间和历史唯一归 N12 应用 repository/业务表及迁移；Scope 核心仍只消费已解析集合，不拥有存储。定义更新采用版本竞争检查，历史解释绑定实际使用的定义/成员快照，不以最新成员重写历史。
跨 Scope→Group 的引用保护由 N12 组装持有：删除被引用组或直接目标必须拒绝；先显式解除引用后才能删除，不静默级联清空范围。新增引用、解除引用与删除必须在同一受控事务/锁定顺序下串行校验，防止检查后新增引用；N09 提供参与该事务的受控写入接缝，不反向依赖 Scope 或读取其业务表。被计划引用的 Scope 版本同样禁止静默删除。
N12 通过 #2347 接缝对静态组和 Scope 变更执行对象授权，并将成功审计与 N09/应用 repository 的状态变更放入同一事务；审计失败整体回滚。N09 独立 T2 用受控调用方验证事务/并发/恢复，N12 T2 验证真实权限、跨 owner 引用保护和审计原子性，不把两者当成同一证明。

### 输入、输出与失败语义

| 唯一 owner | 调用方输入 | 输出与错误/未知语义 |
| --- | --- | --- |
| Group | tenant、对象键、字段定义与事实快照/版本、Criteria AST/版本、固定 as_of、已有成员；独立集合差分接受调用方新旧成员，静态组不经 Criteria 求值 | Match/NoMatch/Unknown 及原因、稳定 added/removed/unchanged；仅明确匹配进入新成员集，未知对象单列。规则/字段/操作类型错误、超预算、混租户输入拒绝；整次重算失败不提交成员差分。 |
| Scope | 同租户完整解析的 Target/Limitation/Exclusion 集合及来源引用/版本 | 目标并集与限制并集的交集减排除并集，输出稳定去重成员和来源解释。未配置 Limitation 不缩小目标，配置为空则结果为空；不完整、解析失败或混租户输入拒绝，不伪装为空集合；不取 Group 仓储。 |
| Policy | tenant、不可变策略版本、显式目标快照、不可变载荷引用、已有执行事实、请求身份/as_of、显式移除规则 | 激活/暂停/归档转换及新增/保留/取代/取消意图；相同版本和输入保持计划身份。非法转换、冲突/过时版本拒绝；旧事实不覆盖新期望。未执行、结果未知、状态已核实分开；取消不证明终端撤销。不解析 Scope，不取 Group/Resource 仓储。 |
| Resource | tenant、资源键、software/script/configuration、不可变版本、平台/架构/variant、源/包/版本、摘要与产物引用 | 校验后的资源版本及激活/弃用/归档结果；冻结后不能改字节/摘要，被引用版本不能静默删除。身份/摘要冲突、非法转换、缺失或不支持变体明确拒绝；不隐式回退公共同名包。安装/检测/卸载定义只是数据，不代表执行。 |
| WinGet 源 | 精确 source/package/version/architecture/installer、受支持 manifest、产物摘要/引用、源与下载凭据引用 | 校验结果、REST Source 查询/响应转换、供组装提交的发布元数据。未知协议/manifest 版本明确不支持；错误摘要、非成功响应、超时各自可诊断，不转为空结果或发布成功；不调用 winget CLI。 |
| Brew 源 | 精确 Tap/Formula/Cask 标识、受控模板、架构/依赖清单、Bottle/Cask 产物摘要与引用、Tap/产物凭据引用 | 受控元数据、校验结果及 Git 接缝的不可变 commit 身份；转义/路径/身份冲突、摘要或依赖不匹配拒绝，Git 结果未知保留待对账。只支持专用 Tap，不执行任意 Ruby、brew 安装或覆写未经批准的共享 Tap。 |
| 软件发布 | tenant、候选描述、源快照/manifest/产物摘要、验证证据、发布者/审批者引用、环境、请求身份/as_of、外部结果证据 | 候选/验证/批准/发布/隔离/弃用状态与 Test/Pilot/Production 晋级、撤回和恢复决策。非法转换、身份约束不满足、证据不足阻断；任一批准输入变化使批准失效。外部提交未知按原发布身份对账，不换身份盲目重试。 |

发布核心保存外部结果与审批快照的关联，只有组装确认结果符合批准内容才转为后端 Published。
这里的 Published 是源元数据发布事实，与消息 Published、设备 Applied/Converged 不同；撤回只阻止新发布授权，不承诺终端卸载、降级或缓存即时消失。
WinGet 首期接已有兼容 REST Source；Brew 首期使用专用 Tap 与受控模板。具体协议版本、endpoint、模板支持矩阵和输入/响应预算在 N06/N07 对照官方上游源码冻结，N01 不承诺任意生态特性。

### N03/N04 实现语义

Scope 完整解析、限制空值和解释 API 见 [Scope 核心](../../../crates/scope/README.md)；来源版本的成员不可因解析时间变化而改变。
Policy 暂停只关闭 Apply 调度并保留身份，恢复沿用原版本；明确范围退出和归档按显式移除规则产生取消意图，
新版本取代时旧非终态也产生取消意图。当前仅接纳停止执行并保留已有效果，不生成 cleanup 载荷计划。
取消后同版本重入不自动重试；执行进度与效果核实分开。具体输入、意图和身份编码唯一归 [Policy 核心](../../../crates/policy/README.md)。
纯核心验证输入快照，不证明授权或跨请求 CAS；N10/N12 原子应用时仍须核对策略 revision、目标快照与执行事实前置条件，
并持久保护版本/载荷不可变性、执行键唯一性和事件原子性。该澄清不扩展 N03/N04 到存储、清理动作或派发。

### 基础值、身份与确定性

- tenant/time 复用既有公共值类型（`rss-request-context::TenantId`、`rss-contract::Timepoint`），不在各核心重复定义或 re-export。业务对象键由对应能力拥有；首期接线为设备键，不引入端侧用户/通道展开。完整键包含 tenant，比较、去重、请求幂等与持久唯一性均不得丢失租户边界。
- 身份由调用方提供；核心仅检查输入结构、tenant 一致性及声明的 actor 约束，不把参数存在当作认证/授权证明。N12 通过 #2343/#2347 接入会话、对象权限与审计，通过 #2348 映射可信 Device/tenant；不以序列号、自报 tenant 或 channel ID 替代设备主体。N09–N11 可使用受控 fixture/服务身份独立验证，无需等待设备身份实现。
- 字段定义包含键、类型、单位及可用操作；值为字符串、布尔、整数、UTC 时间或同类型集合，不隐式字符串转数值/时间。事实携带来源、快照身份和采集/有效期信息；合法 Null 与 Missing/Stale/Unsupported 分开，错误字段与无权限字段不能静默忽略。N12 当前只映射已交付的 `device.model`、`device.os.version` 字符串，不将历史字段字典当作当前资产能力。
- 所有时间决策显式传入固定 `as_of`，核心不读系统时钟；相同规则/版本、快照、时钟和旧事实得到相同结果与稳定身份，集合去重和解释输出顺序稳定。未知值不能默认成为匹配；调用方不得将不完整资产快照冒充完整输入以触发批量成员删除。
- N02 首版为受限比较、集合和 AND/OR；复杂表达式及组引用明确拒绝。AST 深度、节点、集合和字符串预算由 N02 实现冻结并测试；不引入任意表达式/SQL 拼接。历史 Criteria/expr/SQL 只作固定时钟行为对照，不保留旧解释器、兼容转换或静默语义降级。
- 凭据只保存引用，不进入内容摘要材料或日志；源元数据授权与产物下载授权分域。组装校验目标地址与访问策略，限定网络/下载预算并脱敏错误；真实管理 API 在暴露成员/字段解释前验证对象权限，关键变更与成功审计原子提交，失败不放宽权限。

## 首期运行结构

`api`、`gateway`、`worker`、`migrate` 是职责边界，后续可由一个 app package 提供多个 binary。migrate 为一次性进程；API 与设备入口按认证与网络边界配置。无需给 Group、Policy、Resource 各部署一个服务，也不要求第一项消费证明就启动所有进程。

只读链先使用 PostgreSQL 和必要 RSS 组件。首次需要可靠业务发布时引入现有事务消息 PG/AMQP adapter 与 RabbitMQ；不为本次重写增加 Redis Streams adapter。MQTT 推送、Kafka 日志和 Saga 仅在具体交付需要时引入。

复用 rss-runtime 的资源生命周期，不把产品配置、TLS、信号、readiness 或最终路由转回 RSS。当前 rss-axum 已有 H1/H2/Auto，可按需选用；其 TcpListener 接缝不自动提供 TLS/mTLS/ALPN。产品在可信 TLS 入口后使用 managed HTTP，或在必须直连终止 TLS 时组合 Hyper/Rustls 与 rss-runtime，按实际证书主体传递与隔离测试选择，不能仅凭 H1 能力宣称网关已可交付。

## 上行：采集到资产

```mermaid
flowchart LR
  D[真实终端] --> A[凭据校验与 DevicePrincipal]
  A --> C[产品 CollectionRun 与 coverage]
  C --> O[RSS Observation 持久接收]
  O --> J[已提交 journal]
  J --> P[RSS Projection]
  P --> I[产品 Inventory 与 checkpoint 同事务]
  I --> Q[授权资产 API / 前端]
```

DevicePrincipal 绑定服务端 tenant、DeviceId、RegistrationId、凭据和通道。正文中的序列号、SyncML Source 或自报 tenant 不得替换认证主体。mTLS 在代理终止时，需可信代理连接、剥离外来身份 header 和可验证的主体传递；不能信任任意客户端 header。

原生 MDM 首期按明确字段 coverage 采集完整 snapshot。CollectionRun 负责会话关联、分片汇总、超时与完整性；完整快照仅替换声明覆盖的数据域。部分/失败结果记录产品运行状态与质量，不假装完整 snapshot，不删除未返回字段。原生设备不认识 RSS sequence/epoch，由产品在可信注册实例和持久采集运行下分配稳定报告身份；重复回执恢复同一报告，不能每次生成新 batch。

第一条只读闭环也包含最小持久审计：注册授权、凭据绑定/撤销、认证拒绝与授权查询可追溯。关键身份变更和成功审计同事务；审计失败拒绝变更。拒绝/查询审计失败不放宽权限，返回可诊断失败并告警，不允许静默丢失审计后宣布成功。

Observation 的持久 receipt、Projection 的资产提交、设备命令应用、设备合规是独立事实。投影延迟必须可见；原始报告先完成接收事务，再消费已提交 journal，通过 Projection 的借用事务同时更新 Inventory 和 checkpoint。不得把两阶段描述为端到端同一事务，也不再加中间报告队列。

## 下行：期望到可核实状态

先计算设备 EffectiveDevicePlan，再按设备 authority coordinate 创建整批操作，避免各策略 worker 独立推进设备 generation/epoch 而相互作废。

Reconcile observe/diff → 受保护事务：产品操作 + Device Command + Outbox + 关键业务审计 → 提交结算 → relay → 产品 gateway 持久交付关联 → 终端回执 → 实际状态回读 → Applied / Converged。

事务消息 PgRuntime 仅在其借用事务组合内拥有结算权；不是整个系统所有事务的唯一 owner。Projection 与 Observation 各有自己的事务边界。产品 repository 通过公开 with_connection 等受控接缝参加既有事务，不另写 UnitOfWork；审计纳入产品事务表，按需要另消费 ledger，不将其“可用”当作首期前置。

`Queued`、`Published`、`Received`、`Applied`、`Converged` 分别代表接纳、内部发布、匹配接收、已验证实际目标、重新观察无差异。device-command 的 expected-state-digest 不适合任意 Get、脚本或无法确认结果的擦除；CollectionRun/ActionRun 留在产品，保留结果不明，不伪造 Applied。

组合时必须显式启用 reconcile-postgres 的 `transactional-messaging` feature，并使用 `messaging::protect/wake_with` 回调提供的消息 PgTransaction。默认 reconcile PgTransaction 是另一种类型，不能传给 device-command store；PgOutboxStore 还必须属于精确同一个 PgRuntime 实例，连接同库不够。当前库没有这个产品三方组合的完整 T2，F07 必须补验证。

| 权威坐标 | 粒度与用途 |
| --- | --- |
| Device Command generation/epoch | tenant + device；设备计划替代，不由每个策略各自推进 |
| Reconcile claim epoch | tenant + reconciler + entity；调度租约，entity 到设备由产品映射 |
| Messaging execution fence | storage identity/lineage + tenant epoch；恢复与存储执行隔离 |
| Observation stream epoch/sequence | 产品授权的来源/数据集/注册流；报告顺序与完整性 |
| Projection source lineage/generation | journal身份与投影定义；重建与读模型切换 |

这些坐标相关联但不相等，不能共用一个 epoch 字段。命令幂等 ID 在 tenant 内唯一，不能只使用设备内局部序号；reconcile 内部 mark_applied 也不表示设备 Applied。

原生回执保存 registration/session/outbound MsgID/CmdID/delivery attempt 的完整关联；晚回执只能影响其所属实例。服务端 fencing 不能撤销已到终端的动作；Rust Agent 另实现本地持久 epoch 检查。

## 存储、迁移与资源

产品 migrator 编排 RSS owner 提供的 schema/upgrade SQL 与产品表，记录版本和执行状态；运行角色不执行 DDL，不具备 superuser/BYPASSRLS。组件默认 pool ownership 不同，PgPool.clone 不是隔离：在组合根逐项声明谁拥有、谁借用、谁停 worker、谁关闭 pool。首次基线优先各 owner 独立 pool，事务内 bridge 使用被借用的连接并验证角色授权。

共享数据库不意味着共享事务。Observation → Projection 的 SQL bridge 要求目标连接可在同一数据库按正确租户读取 Observation journal；分库或远程投影须另定义至少一次交付与目标去重，不假设本地原子性仍成立。

## Agent、前端与迁移

Agent 先做只读上报与持久回执，再做可信脚本/单一 MSI。安装前后检测、崩溃恢复、结果持久化与重传分开；在安装已发生而日志未提交时先检测，不盲目重跑。updater/bootstrap 独立于被替换进程，签名、坏包、启动失败、凭据和状态保留均独立验收。

前端暂不重写；实际 WinMDM 前端当前未取得，现有 rss-web 属 RSS 浏览器客户端且明确排除 MDM，不能用它替代。先取得仓库 revision、API/错误/分页/会话契约再冻结兼容。本批 Group 直接采用上述类型化契约；旧 Criteria/expr/SQL 仅提供行为对照，不承诺表达式向后兼容，不支持的旧规则明确拒绝。存量规则盘点与显式重建归 M01，不在核心保留旧解释器或自动转换路径。

按设备群停止 Go 的真实写入与派发 → 对账未确定任务 → 映射身份和最终事实 → Rust 先观测再控制 → 扩群。旧命令行不直接伪造 RSS receipt；旧审计保留来源。回退前停止 Rust 派发、核对新证书/协议/动作，不能只切流量。恢复旧备份先暂停派发并核对 broker/receipt/设备实际状态，再决定恢复。

## 取舍与待冻结项

Windows 只读先证明身份与资产；macOS 原生与 Agent-only 沿同一模型推进，R1/R2 双平台目标保持。具体 OS/edition、证书签发方式、客户端版本、前端 revision、artifact 分发源、生产容量和兼容期限须在对应交付冻结。取舍改变时更新本 ADR 与受影响验收，不另建并行真源。
