# WinMDM 历史基线

此页保留原 PRD 的历史实现判断、旧规划批次与性能目标，供迁移查阅。它们不构成 rss-mdm 的完成状态、工期或性能承诺；产品交付顺序以 [当前 PRD](../product/rss-mdm-prd.md) 为准。来源编号见 [历史来源索引](historical-sources.md)。

# 03.1　现有能力基线

*以下为导入 PRD 所载的 WinMDM 静态分析；不是 rss-mdm 的实现状态，也不代表原 PRD 编写时重新验证了这些行为。*

| 能力 | 当前判断 | 主要证据与限制 |
| --- | --- | --- |
| 平台形态 | 已有 | 6 个 Go 服务及独立 Windows Agent；前端不在包内。[D01](historical-sources.md#d01) |
| MDM 注册与管理会话 | 已有 | Discovery/XCEP/WSTEP、SyncML 主链路、设备证书及管理接线。[C02](historical-sources.md#c02)[C13](historical-sources.md#c13) |
| 采集与资产读模型 | 已有 | 采集模板、DDF、硬件/网络/合规数据及 CQRS 读模型。[C14](historical-sources.md#c14)[C15](historical-sources.md#c15)[C29](historical-sources.md#c29) |
| Agent 注册与签到 | 已有 | 独立注册、基础硬件采集、轮询、凭据存储。[C05](historical-sources.md#c05)[C06](historical-sources.md#c06) |
| 静态 / 智能组 | 已有 | CRUD、SQL 侧重算、成员差分、事件联动及调度接线。[C03](historical-sources.md#c03)[C10](historical-sources.md#c10) |
| 策略版本与 Scope | 已有 | 策略生命周期、Target/Limitation/Exclusion、执行与 reconcile。[C04](historical-sources.md#c04)[C11](historical-sources.md#c11)[C12](historical-sources.md#c12) |
| CSP 执行基础 | 已有 | 内置 12 项 Provider；专用类型、OMA-URI 与通用 csp_config 并存。[C08](historical-sources.md#c08)[C09](historical-sources.md#c09) |
| 远程动作与命令结果 | 已有 | MDM 动作服务、持久命令、结果与重试机制；真机支持待验收。[C13](historical-sources.md#c13)[C24](historical-sources.md#c24)[C25](historical-sources.md#c25) |
| 合规与历史查询 | 已有 / 部分 | 当前合规字段、快照和历史 API；不等于规则化合规/条件访问全产品。[C01](historical-sources.md#c01)[C13](historical-sources.md#c13) |
| 统一设备视图 | 已有 / 部分 | 已有 CQRS 模型和投影；关联冲突、失效与双通道一致性仍须场景验收。[C14](historical-sources.md#c14)[C15](historical-sources.md#c15) |
| 高级搜索 / 保存查询 | 已有 | 查询、字段发现、选列、保存搜索及 Dashboard API。[C01](historical-sources.md#c01)[C19](historical-sources.md#c19)[D15](historical-sources.md#d15) |
| 资源 / 文件 / 版本 | 已有 | 资源域与文件操作；不等于应用部署、安装检测、卸载闭环。[C21](historical-sources.md#c21) |
| 本地认证 / SSO / RBAC | 已有 | 登录、会话、角色、OIDC/JIT/组映射及内部主体校验。[C01](historical-sources.md#c01)[C17](historical-sources.md#c17)[C18](historical-sources.md#c18) |
| 初始化 / 设置 | 已有 | Setup、基础设施测试、生命周期与日志设置；WNS 配置有重载逻辑。[C01](historical-sources.md#c01)[C02](historical-sources.md#c02)[C20](historical-sources.md#c20) |
| 审计可靠性增强 | 部分 | 已有缓冲、重试、文件溢写与重放，仍存在 dropped 路径。[C16](historical-sources.md#c16) |
| 事务消息与状态收敛 | 已有基础 | MDM/Group/Policy 有 outbox 与 relay / reconciler 接线；不据此宣称全系统故障闭环已验证。[C02](historical-sources.md#c02)、[C03](historical-sources.md#c03)、[C04](historical-sources.md#c04) |

## 原 PRD 编写时新增领域的实现判断

| 能力 | 历史快照观察 | v0.2 处理 |
| --- | --- | --- |
| macOS Provider | provider.go 仅保留 PlatformMacOS；TranslateResult 的 MDMCommands 仍是 SyncMLCommand，不能直接承载 Apple Plist。[C32](historical-sources.md#c32) | macOS 必须扩展协议类型与实际适配器；不是打开一个 feature 就完成。 |
| 虚拟执行基础 | 已有 PlatformProvider、Capability 的 SupportsMDM/SupportsAgent 和预留 AgentTasks。[C32](historical-sources.md#c32) | 复用意图/平台接口的思想，补适用性、计划、认证回执、状态与恢复，不把预留字段当完整实现。 |
| Agent 真执行 | poller.go 293–313 仍只校验并记录 command accepted。[C06](historical-sources.md#c06) | WMD-R/WMD-V 的执行/结果/离线恢复仍为首要依赖。 |
| osquery / Brew / WinGet 管理 | 原分析在 src 与 src-agent 的 Go 源码定向检索未发现对应完整实现；历史文档有 WinGet 规划。 | 均按新增/规划目标，不给完成率；不以关键词检索替代运行验证。 |


---

# 03.2　关键未闭环与旧结论校准

*避免把旧报告中的缺口原样复制为当前事实*

| 主题 | 当前应使用的表述 | 产品影响 |
| --- | --- | --- |
| Agent 执行 | Poller 仅校验命令并记录 accepted 日志；无实际执行与结果回传调用。[C06](historical-sources.md#c06) | 脚本、Script EA、Agent 安装尚不能交付。 |
| Agent 任务生产 | TaskRepository 仅 GetByID / DispatchPending / Acknowledge，无 Create。[C07](historical-sources.md#c07) | 领取接口不代表任务生产与执行闭环成立。 |
| 离线队列 | SQLite 队列组件存在；轮询主链未接成执行结果补传管线。[C06](historical-sources.md#c06)[C28](historical-sources.md#c28) | 不能宣称断网执行结果可靠送达。 |
| EA / 应用 / Webhook | 当前应用与领域目录未见相应完整业务域；路线图有明确需求。[D05](historical-sources.md#d05)[D08](historical-sources.md#d08) | 不能用 CSP/Resource/事件总线替代业务交付。 |
| 密钥 / 更新环 | BitLocker 配置与采集基础存在；LAPS/恢复密钥托管及更新环不能按“Provider 已有”认定完成。[C08](historical-sources.md#c08)[D05](historical-sources.md#d05) | 安全托管和补丁节奏需独立验收。 |
| 审计 | 旧报告称缓冲满即丢；当前已有重试与 overflow，但失败仍可丢弃。[C16](historical-sources.md#c16) | 需补关键管理操作可持久追溯的保证。 |
| 配置 / SSO / 智能组 | WNS 热重载、SSO ResolveRoles 调用、SQL 重算已出现。[C02](historical-sources.md#c02)[C03](historical-sources.md#c03)[C17](historical-sources.md#c17) | 不再笼统写“尚未实现”；改为行为验收。 |
| 控制台 | 外部 ../winmdm-web 不在历史归档中。[D01](historical-sources.md#d01) | 界面能力与体验只能列需求，不能确认实现。 |

## 产品判断

现有 WinMDM 已超出“仅注册与资产展示”的最早 MVP，具备 MDM 配置执行和管理面的较多实现。最明显的扩展瓶颈是 Agent 任务闭环及其上层业务，商业可交付性还取决于控制台、关键审计、真实设备、恢复与升级证据。

原 PRD不复用 D08 的 90%/30–40% 等覆盖率为当前得分：这些是对“路线图完成后”的估计，不能描述原 PRD 编写时代码快照。

---

# 04.1　从 Phase 2 提取产品规划

*保留原规划名称；用新需求编号消除 Sprint 编号重用*

| 原条目 | 产品能力与原 PRD对应 | 当前 / 处理 |
| --- | --- | --- |
| 025 智能组 | SQL 重算、成员 DIFF、合规触发、重算日志 → WMD-G | 已有基础，转为补齐与验收。 |
| 026 凭证托管 | LAPS 轮换、BitLocker 多盘密钥、加密与访问审计 → WMD-K | 规划；原文明确第二批延期。 |
| 027 OMA-URI | 任意 CSP、版本、Scope、安装/移除结果 → WMD-C | 专用与通用实现并存；功能保留，是否统一迁移另决策。 |
| 028 高级搜索 | 条件、选列、保存查询、Dashboard → WMD-Q | 已由 specs/029 实现；原“150+ 字段”不等于当前支持。 |
| 029 脚本库 | 脚本版本、参数、执行记录与策略关联 → WMD-R | 规划；不是当前 specs/029 搜索。 |
| 030 扩展属性 | Script/Manual、值存储、分组和搜索 → WMD-X | 规划；不是当前 specs/030 Setup。 |
| 031 Webhook | 订阅、鉴权、事件过滤、重试与投递记录 → WMD-I | 规划。 |
| 032 软件三通道 | MDM、Agent、Winget；应用生命周期与检测 → WMD-S | 资源基础已有，应用闭环待建。 |
| 033 更新环 | Preview/Pilot/Production、组关联、暂停恢复 → WMD-U | 规划；原文明确第二批延期，不依赖 026。 |
| 034 预注册 | 提前登记元数据、注册匹配、状态追踪 → WMD-E05 | CSV 方案与禁用要求冲突；预注册目标保留，输入方式待确认。 |

## 原文已明确的执行批次

D05 §1.2 写明第一批为 025 + 027 + 032（MDM 子能力），第二批为 026 + 033。原 PRD保留该顺序作为历史来源事实；原 PRD 编写时已新增 macOS、统一执行与软件源范围，新整体顺序以第 05 节为准。已有能力只做兼容、补齐与回归，不再次从零建设。

## 草案状态与接口边界

D05 元数据为 official/source_of_truth，但正文标注 Draft；原 PRD仍按“产品规划草案”处理。源文中的 Go 类型、数据库表、接口路径是方案载体，不直接冻结为 Rust 目标实现。CSV 相关冲突不随需求搬运。[D05](historical-sources.md#d05)[D15](historical-sources.md#d15)[D16](historical-sources.md#d16)

---

# 04.2　MDM 原生路线与 Agent 路线

*两条路线描述不同产品面，不替代完整 PRD*

| MDM 原路线阶段 | 提取的产品结果 | 当前定位 |
| --- | --- | --- |
| P1–P3 | 安全初始化、手动注册、证书、管理会话、命令与采集 | 当前已有大量实现；重写时保留行为，重新取得运行证据。 |
| P4–P5 | 分组、Scope、CSP / OMA-URI / DDF、策略执行 | 已有基础；通用 CSP 不能被等同于所有业务完成。 |
| P6 | 合规、WNS、证书生命周期、解注册、设备动作 | 已有 / 部分；对照真实场景补证据。 |
| P7 | LAPS、Hello、WDAC/AppLocker、更新、隐私、Kiosk、电源、代理、应用管理 | 扩展规划；按可用配置与结果要求验收，不设 Provider 数量目标。 |
| P8 | 大对象会话、SCEP、DHA/TPM 证明、规则化合规、条件访问信号 | 规划；属于独立交付切片，非通用引擎自动获得。 |
| P9 | 重注册、Entra 联合注册、报告 API | 重注册已有基础；联合注册与报告增强待交付。 |

| Agent 原路线 | 依赖与产品交付 |
| --- | --- |
| A：任务执行闭环 | 创建 → 领取 → 执行 → 回传 → 持久化；PowerShell/noop、签名验证、超时、离线结果补传。 |
| B：EA 与深度采集 | 依赖 A；脚本型属性、软件增量、深度硬件、读模型/智能组/搜索联动。 |
| C：软件分发 | 依赖 A 和资源域；下载校验、检测规则、安装卸载、分阶段发布和失败处理。 |
| D：高级能力 | Winget、补丁评估、按需诊断、自更新；WebSocket 为可选增强，轮询仍保底。 |

D08 建议在 MDM 基本会话和命令路径可用后并行启动 Agent A。当前已有这部分基础，后续应先确认重写接口边界并补 Agent A，而不是等待所有扩展 CSP 完成。此处为依赖判断，不是新增工期承诺。

> 依据：D07 原生 9 阶段；D08 Agent A–D。原路线中的周数与商业覆盖率未转为原 PRD 编写时交付承诺。

> 本节描述历史 Windows 路线；其中 Winget 在原 PRD 编写时已提升至正式二级交付，macOS 不再沿用 v0.1 的三级远期定位。

---

# 历史性能目标

*原始 Windows 指标作为历史目标；新增跨平台负载需重新验证*

| 主题 | 来源目标 / 当前边界 | 本稿验收要求 |
| --- | --- | --- |
| 设备规模 | D02：MVP 5 万、Phase 1 15 万、单服 5,000 → 20,000；部署章节另以 5,000 分档。 | 存在规模口径差异；确认硬件、在线比例、场景与采样周期后再设发布门槛，不宣称已支持。 |
| 注册并发 | D02：1,000 台/分钟。 | 明确窗口、成功判据及证书/数据库配置，测到端到端注册完成。 |
| 策略时延 | D02：在线 WNS+SyncML <10 分钟；默认轮询约 15 分钟。 | 分别测有推送、无推送、离线情形；15 分钟轮询不能天然满足 10 分钟上界。 |
| 组评估 | D02：单设备增量 <5 秒，5 万台全量 <15 分钟。 | 固定规则复杂度、设备数与并发变化；测成员落地及后续 Scope 传播。 |
| Agent 开销 | D02：静默 CPU <0.1%、内存 <50MB；活跃 CPU <10%、内存 <150MB。 | 测真实 Windows 下的采集、脚本、安装及离线恢复，不能用未执行任务的 Agent 达标。 |
| 可用性 / 数据保护 | D02：服务 >99.9%，RPO <1 小时；未给出一致且完整的 RTO。 | HA、RPO/RTO、备份范围与恢复验证待定稿；关键凭据、任务和审计均纳入。 |
| 安全 / 隐私 | D02：TLS、RBAC、敏感数据保护；禁止采集个人文件、聊天、浏览历史、精确 GPS。 | 受控测试越权、无效证书、敏感输出与数据最小化；远程协助需用户同意。 |
| 兼容与升级 | D02：Windows 10 1809+/Windows 11；D01 前端外仓。 | 逐项列 OS/版本类型/通道/CSP 支持表；API、Agent 与服务端兼容窗口待确认。 |
