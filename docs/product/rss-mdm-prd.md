# RSS MDM 跨平台终端管理产品需求文档

Windows + macOS｜统一执行、双通道管理与私有软件仓库

**版本：v0.2｜日期：2026-09-07｜状态：评审草案**

工程目标见 [项目目标](project-goals.md)，实施切片见 [Rust 重写路线](202609072231-002-rust-rewrite-roadmap.md)。自有服务端与 Agent 使用 Rust，直接消费 RSS；功能需求与本文件的验收编号继续保持稳定。

## 阅读说明

本文定义 rss-mdm 的产品目标，包含 144 项 WMD-* 需求、22 个功能模块及相应验收场景。需求编号保持稳定；数量不代表完成度。

当前仓库尚未实现这些产品能力。表中的“历史基础”仅描述 WinMDM 快照中的 Windows 实现或规划，不代表 rss-mdm 已完成，也不自动延伸到 macOS。所有发布能力须在当前产品中取得验证证据。

历史实现、旧批次和旧性能指标见 [WinMDM 历史基线](../reference/winmdm-baseline.md)；代码与文档出处见 [历史来源索引](../reference/historical-sources.md)；厂商资料见 [外部参考来源](../reference/external-sources.md)。缺少运行证据的目标不得宣称已支持。

需求分级和产品职责见 [范围规则](../rules/project-scope.md)，验证与产品 T3 边界见 [验证规则](../rules/verification-scope.md)。未冻结的参数仍保持待评审，不因文档入库视为已批准。

# 00　核心能力与对标决策

## 00.1　核心能力映射

| 能力 | 产品范围 | 主要需求 |
| --- | --- | --- |
| macOS 对标 | 提升为正式目标：注册、Profile/DDM、资产、安全托管、更新、原生软件及 Mac Agent。 | WMD-MAC01–15 |
| WinGet/Brew 私有仓库 | 进入正式二级交付；源/元数据/产物/审批/分配/终端执行/恢复完整管理。 | WMD-S06、WMD-REP01–10、WMD-BRW01–10 |
| 虚拟执行层 | 业务接口与逻辑模板跨 OS 共用；适配器按能力解析执行，保留平台专属语义。 | WMD-V01–12 |
| 策略下发通道 | 仅 Agent/MDM 两类；DDM 是 MDM 子机制，WinGet/Brew 是执行器，推送不是执行证明。 | WMD-CH01–07 |
| 数据采集与扩展字段 | Agent 内置/osquery/脚本与 MDM 共用字段字典、观测、资产模型；Manual/API 属于赋值来源。 | WMD-X01–05、WMD-COL01–11 |

## 00.2　对标对象各自提供什么参考

Jamf Pro 用于对标 Apple 管理产品的使用方式：原生配置描述文件、按频率/触发器/Scope 运行的管理任务，以及扩展属性驱动智能组。NanoMDM 用于对标可复用协议组件：MDM Check-in、命令、APNs、认证和存储边界。Fleet 用于对标跨平台资产、osquery 查询、脚本/软件工作流和自定义设备字段。三者不是同一产品层次，不能用同一张“功能覆盖百分比”比较。[E01](../reference/external-sources.md#e01)、[E02](../reference/external-sources.md#e02)、[E03](../reference/external-sources.md#e03)、[E04](../reference/external-sources.md#e04)、[E05](../reference/external-sources.md#e05)、[E06](../reference/external-sources.md#e06)、[E07](../reference/external-sources.md#e07)、[E08](../reference/external-sources.md#e08)、[E09](../reference/external-sources.md#e09)、[E10](../reference/external-sources.md#e10)、[E11](../reference/external-sources.md#e11)

| 能力面 | Jamf Pro 参考 | NanoMDM 边界 | Fleet 参考 |
| --- | --- | --- | --- |
| 配置与执行 | Profile 与脚本型 Policy 分工。[E01](../reference/external-sources.md#e01)、[E02](../reference/external-sources.md#e02) | 原生命令接口，不是上层策略编排。[E05](../reference/external-sources.md#e05)、[E06](../reference/external-sources.md#e06) | 原生配置与 DDM、软件/脚本工作流。[E07](../reference/external-sources.md#e07)、[E11](../reference/external-sources.md#e11) |
| 注册基础 | 用 Apple 管理流程作为产品体验目标；具体支持按 Apple 规范冻结。 | 不含完整注册 Profile 生成或 ADE API 接入。[E05](../reference/external-sources.md#e05) | 作为统一设备管理体验参考；本文不据此认定所有注册路径免费。 |
| 资产与扩展属性 | 输入型/脚本型 EA，可用于组和变量。[E03](../reference/external-sources.md#e03)、[E04](../reference/external-sources.md#e04) | 业务资产模型和自定义字段由上层建设。[E05](../reference/external-sources.md#e05) | 查询与 custom host vitals 分工明确。[E08](../reference/external-sources.md#e08)、[E10](../reference/external-sources.md#e10) |
| 软件运维 | 策略可分发软件，支持触发频率与范围。[E01](../reference/external-sources.md#e01) | 不含 VPP 与应用生命周期产品。[E05](../reference/external-sources.md#e05) | 自定义包、维护目录和 App Store/VPP；部署指南标记 Premium。[E07](../reference/external-sources.md#e07) |
| 自动化 | Scope/触发器模型。[E01](../reference/external-sources.md#e01) | Webhook 与原始命令作为组合接口。[E06](../reference/external-sources.md#e06) | 策略结果触发修复或软件；不等于原生配置策略。[E09](../reference/external-sources.md#e09) |
| 对本产品的用途 | 借鉴管理对象和流程，不照搬全部产品线。 | 默认复用方向；产品补齐缺失控制面。 | 借鉴跨平台采集与统一体验，不默认嵌入整个平台。 |

## 00.3　关键取舍

统一“意图、目标、执行状态和数据语义”，不统一所有原始指令。一个软件可以有 Windows WinGet 与 macOS Brew 两个实现；同一套 Scope/审批/结果视图可共用。一个 Apple Profile 不必被改写为跨平台最低公分母；高级管理员仍可使用受控原生模板。

默认单一写入路径，可以使用另一通道只读核实。双通道超时切换、未知状态、旧命令晚执行必须进入明确恢复流程；不能用双发命令制造“高可靠”的假象。

优先复用 NanoMDM、osquery、WinGet 和 Homebrew 的协议/执行机制。RSS 只提供已接纳的通用库；策略语义、软件仓库、macOS 协议、字段字典、设备身份、控制台和 T3 仍由 MDM 产品拥有。[范围规则](../rules/project-scope.md)

# 01　产品定位与业务边界

RSS MDM 面向企业私有化部署，统一管理 Windows 与 macOS 的设备身份、资产、分组、配置、脚本、软件、更新、安全和退役。

产品价值：管理员以统一设备/组和业务目标操作；服务端按能力和权限生成执行计划；原生 MDM 与 Agent 各自可用；每次管理都能回答“谁发起、目标是谁、走哪条通道、实际执行了什么、结果凭什么成立、失败如何恢复”。

| 范围 | v0.2 边界 |
| --- | --- |
| 操作系统 | Windows 与 macOS 正式进入目标；不顺带承诺 Linux、iOS/iPadOS、Android。已存在 Apple 底层协议能力不等于移动平台产品准入。 |
| Mac 首批对象 | 企业自有 Mac；手动注册和 Agent-only 先形成基线，ADE/DDM/托管/软件与更新在二级闭环交付。BYOD 深化、多用户完整管理另行评审。 |
| 通道 | Agent、MDM；注册与认证独立，统一设备读模型关联，不强制所有设备双通道。 |
| 软件源 | WinGet 私有 REST Source、Homebrew 私有 Tap 与内部产物；复用成熟 Git/制品服务，可接已有源与受控托管发布。 |
| 数据 | Agent 内置、osquery、自定义脚本、MDM；统一标准与扩展字段。Manual/API 可为业务元数据赋值。 |
| 部署 | 产品私有化部署；允许依赖 Apple 官方服务。全隔离网络不承诺原生 Apple 管理持续实时可用。[E17](../reference/external-sources.md#e17)、[E18](../reference/external-sources.md#e18) |
| 明确不恢复 | CSV 导入导出、UI 数据导出、GPO 迁移、公有 SaaS、EDR/杀毒替代、Windows 7 等旧排除项。机器可读资产 API 保留。 |
| 可选增强 | MSP、多租户数据隔离、远程桌面、P2P、多地域、自助与高级 SSO/准入；须独立价值场景与范围批准。 |

## 支持矩阵的发布规则

支持矩阵必须记录 OS 发行版本/构建、芯片、注册方法、监督/管理授权、设备/用户目标、Agent/osquery/包管理器版本、具体操作、前置条件、已通过证据及退役时间。不得用“macOS 支持”一个布尔值替代。

首批测试优先覆盖 Apple Silicon，Intel 按目标客户与依赖支持情况纳入；任何已宣称支持的组合均须真实机器验证。稳定版与预览版分栏，预览版不自动进入生产支持。Windows 版本支持以发布时冻结并验证的矩阵为准，不沿用历史版本下界作为当前承诺。

---

# 02　目标用户、价值与核心旅程

*先完成可用闭环，再扩展自动化深度*

| 角色 | 希望完成的工作 | 可见成功结果 |
| --- | --- | --- |
| MDM 管理员 | 注册设备，维护组、配置、策略与发布范围 | 目标设备正确命中；每台设备的失败阶段可定位。 |
| 安全管理员 | 验证安全基线、补丁、加密和设备风险 | 可区分真实不合规与数据未知；修复有证据。 |
| 桌面支持 | 按用户/主机/资产标识定位故障并远程诊断 | 不用手工拼接通道数据即可看到近期状态与结果。 |
| 审计人员 / IT 经理 | 审查变更、观察覆盖率、趋势与管理效率 | 数据定义一致，可经 API 取得授权范围内证据。 |
| 终端用户 | 完成注册，理解采集范围，获得可控运维支持 | 清楚知道被管理内容；可选自助能力不侵入隐私。 |
| 集成系统 / 部署运维 | 对接资产和事件，安装、升级、恢复系统 | 受控身份和失败反馈明确；配置生效可判断。 |

## J1　新设备进入管理范围

完成平台初始化 → 本地账户或 SSO 登录 → MDM 手动注册 / Agent 独立注册 → 采集基础信息 → 统一读视图展示通道来源 → 自动命中组 → 执行已分配策略 → 核实结果。新设备不要求两个通道同时存在。[D02](../reference/historical-sources.md#d02)[D04](../reference/historical-sources.md#d04)[C14](../reference/historical-sources.md#c14)

## J2　紧急修复与范围变更

管理员检索受影响设备 → 预览 Scope → 激活版本 → 命令入队 → 设备签入执行 → 回传状态 → 复查目标状态。失败可重试或停止；组成员移除只能按已声明的 cleanup/卸载规则清理，不能承诺任意动作都可回滚。[D05](../reference/historical-sources.md#d05)[C09](../reference/historical-sources.md#c09)[C12](../reference/historical-sources.md#c12)

## J3　企业自定义资产与软件运维

定义脚本/扩展属性 → 任务执行回传 → 更新资产 → 智能组变化 → 软件或修复策略执行。该旅程依赖 Agent 执行和 EA 数据链路，须形成完整业务闭环。[D08](../reference/historical-sources.md#d08)[D12](../reference/historical-sources.md#d12)[C06](../reference/historical-sources.md#c06)[C07](../reference/historical-sources.md#c07)

## J4　丢失、退役与重新使用

授权人员确认处置 → 下发受支持的锁定/擦除动作或退役 → 取消不应继续的命令、处理证书并保留审计 → 重新激活时判断是否需要重新注册。不能用“已重新激活”掩盖证书不可恢复。[D02](../reference/historical-sources.md#d02)[C22](../reference/historical-sources.md#c22)[C23](../reference/historical-sources.md#c23)

## J5　跨平台入职与软件标准化

管理员向“研发设备”混合组分配同一套基线 → 系统预览两 OS 能力/前提 → Windows 走 CSP/WinGet，Mac 走 Profile/Brew 或原生安装 → 用户批准等前提清晰展示 → 两平台都以同一应用期望与资产字段核实。管理者无需复制两个顶层业务策略，但平台模板分别维护。

## J6　自定义字段发现问题并闭环修复

定义 custom.corporate_agent.version → 为不同平台绑定 osquery/脚本或可用 MDM 字段 → 字段过期/失败可见 → 智能组定位不满足版本的设备 → 单一写通道修复 → 新观测验证离组。未知设备单列，不能把未知直接当作已合规或自动执行高危修复。

## J7　私有软件版本发布与撤回

提交内部分发包与元数据 → 在隔离验证环境测试 → 审批并冻结摘要 → 发布 WinGet feed/Brew Tap 快照 → 小组灰度 → 完成后推广。发现风险时阻断新授权并撤回发布引用；设备降级/卸载依赖明确方案，已有离线副本另行处置。

---

# 03　迁移基线与能力状态

WinMDM 历史代码用于提取业务语义和回归场景。注册、设备读模型、组、Scope、CSP、认证和设置等历史能力应逐项核对迁移；Agent 真实执行、离线结果补传、关键审计和应用闭环应独立取得证据。

macOS、统一执行、osquery 与私有软件源均按目标能力实施，不能把平台枚举、接口或资源组件视为完整实现。具体历史判断见 [历史基线](../reference/winmdm-baseline.md)。

# 04　实施原则

MDM 原生通道和 Agent 通道分别承担适用的管理能力，共用产品意图、字段和结果语义。Agent 脚本、深度采集和软件执行依赖可信任务创建、领取、执行、回传与恢复闭环；不必等待所有 Windows CSP 扩展完成后才推进 Agent。

历史 Sprint 编号、批次、微服务数量、Go 类型、表结构和 API 草案不直接冻结为新实现。需求使用 WMD-* 编号追踪，发布顺序以第 05 节为准，具体接口与迁移方案由架构设计明确。

# 05　分级、版本与实施依赖

“一级”补接口、身份、状态、Agent 执行与安全等关键盲区；“二级”把每项能力做到可运行、可核实、可恢复；“三级”保留有明确需求后再做的增强。某个二级包的权限、密钥与审计必须随包交付，不准后补。[需求分级](../rules/project-scope.md)

| 版本 | 目标切片 | 发布退出条件 |
| --- | --- | --- |
| R0：契约与可信执行底座 | 冻结共享模型、设备/注册关联、能力预检、单一写 owner；补 Windows Agent 真执行/结果与审计；保留现有 Windows 功能。 | 一个真实 Windows 脚本从创建到补传可核实；旧 API/组/Scope/MDM 不退化；混合目标计划和不支持结果可解释。 |
| R1：双平台管理基线 | macOS 手动 MDM、签名 Agent、Profile 与基础资产；Agent/osquery 与脚本；最小扩展字段字典；跨 OS 一套请求与视图。 | Win/Mac 各自 MDM-only、Agent-only、双通道场景通过；同一采集目标和逻辑配置模板工作，原生差异可见。 |
| R2：企业软件与管理闭环 | WinGet/Brew 私有源审批发布及完整生命周期；ADE、DDM、FileVault/令牌、更新、字段驱动策略；继承 Windows LAPS/BitLocker、应用、Webhook/合规包。 | 两类私有源都经过真实端消费、撤销/恢复验证；各承诺 macOS/Windows 企业用例均有界面、API、运行与故障证据。 |
| R3：可选深化 | 自助、Platform SSO、复杂多用户/源码构建、第三方源连接器、osquery 扩展、远程桌面、MSP 等。 | 单项批准范围、支持矩阵及必要性；不以这些增强阻塞已冻结的 R1/R2。 |

Windows MDM 只读纵切 V1 是 R0/R1 的基础增量，不代替 R0 的 Windows Agent 真执行退出条件。具体依赖按 [实施路线](202609072231-002-rust-rewrite-roadmap.md) 推进；工程先后顺序不降低 macOS、三类采集与 WinGet/Brew 的正式范围。

## 自底向上的依赖顺序

已接纳 RSS 库/成熟外部依赖 → 产品共享契约与持久任务 → Windows/macOS 通道适配和 Agent 执行器 → 能力预检、单一写 owner 与计划 → 统一采集/字段、软件源控制面 → 组/策略/安装/更新/合规 → 控制台、部署与产品 T3。

macOS MDM 与 Agent 可并行建设；ADE 依赖 Apple 组织接入，不依赖 WinGet；Brew/WinGet 的终端执行闭环依赖可信 Agent、产物授权和应用模型；Group/Scope/Policy、Resource、软件源元数据与发布后端可按 N01–N12 提前独立交付，不等待 Agent 或 V1 真机验收；DDM 依赖 Apple 注册与声明/状态服务；更新环不依赖 Windows LAPS。不能把每个节点强行串成单条瀑布，也不能越过任务/身份/结果的基础依赖。

R2 可按“私有软件源闭环”“Apple 自动化与安全”“Windows 企业闭环”分别交付，但每个子发布都必须列出已承诺矩阵。日期、人员和生产容量未给定，不在 PRD 中编造工期。产品 T3 的 issue/PR 与功能开发 PR 分开、与 RSS 组件验证分开。[验证规则](../rules/verification-scope.md)

---

# 06.1　F-E：初始化、设备注册与注册增强

*主要用户：平台管理员、终端用户、部署运维。*

历史基础：Windows MDM 与 Windows Agent 注册、Setup 已有实现；前端注册体验与真实设备支持未验证。联合注册、预注册仍为规划。[C02](../reference/historical-sources.md#c02)[C06](../reference/historical-sources.md#c06)[C20](../reference/historical-sources.md#c20)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-E01<br>安全初始化 | 未完成初始化时仅提供必要健康/Setup 能力；完成基础设施验证、首个管理员创建和凭据配置后进入正常模式。 | 已有<br>一级 |
| WMD-E02<br>MDM 手动注册 | 从 Windows 原生入口完成 Discovery → XCEP → WSTEP → 设备身份与证书建立 → 首次管理会话；失败能定位到步骤。 | 已有<br>一级 |
| WMD-E03<br>Agent 独立注册 | Windows/macOS Agent 可单独安装、注册和签到；共用业务契约，但保留平台安装、凭据存储与权限适配。macOS 实现为新增目标，见 WMD-MAC11。 | Windows 已有；macOS 新增<br>一级 |
| WMD-E04<br>证书与重注册 | 支持设备证书生命周期、撤销后访问控制及重新注册；旧凭据、历史绑定与新注册记录关系需明确。 | 部分<br>一级 |
| WMD-E05<br>预注册 / 联合注册 | 保留序列号与资产元数据预登记、匹配状态、Entra/OOBE 等方向；CSV 不纳入，替代输入方式及联合身份流程待批准。 | 规划<br>三级 |

## 关键规则与边界

设备身份必须保留通道、标识及注册凭据来源；同一序列号或 UUID 冲突时不得静默覆盖另一台设备。

Setup 完成后关闭未认证初始化入口；改变通信域名、证书或关键基础设施时明确是否需要重启/重新注册，不能只显示“保存成功”。

## 验收场景

AC-E01-01　分别用 MDM-only、Agent-only 设备完成注册与查询；第二通道缺失不导致注册失败。

AC-E01-02　重复请求、无效凭据、失效证书和初始化后再次调用 Setup 均有可诊断结果；不会产生未经授权的管理身份。

> 依据：[D02](../reference/historical-sources.md#d02) F-E；[D04](../reference/historical-sources.md#d04)；[D16](../reference/historical-sources.md#d16)；[C02](../reference/historical-sources.md#c02)/C05/C06/C20/C22。

---

# 06.2　F-D：统一设备视图与生命周期

*主要用户：MDM 管理员、服务台、安全管理员。*

历史基础：已有统一设备 CQRS 模型、投影、通道状态及退役/重新激活编排；不应再标成“尚未建立统一视图”。[C14](../reference/historical-sources.md#c14)[C15](../reference/historical-sources.md#c15)[C22](../reference/historical-sources.md#c22)[C23](../reference/historical-sources.md#c23)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-D01<br>统一列表与详情 | 可按设备查到 MDM/Agent 覆盖、各通道身份、最近通信、硬件/网络/软件摘要；保留数据来源。 | 已有<br>一级 |
| WMD-D02<br>通道与新鲜度 | 区分各通道在线状态、最后采集时间与管理生命周期；一个通道在线不代表另一通道命令已执行。 | 部分<br>一级 |
| WMD-D03<br>生命周期 | 支持离线、休眠、回收、退役、软删除与重新激活；阈值可配置，历史记录保留范围可解释。 | 已有<br>一级 |
| WMD-D04<br>远程设备动作 | 按支持清单提供重启、锁定/擦除、更新检查与诊断等动作；返回命令标识、状态和失败原因。 | 已有<br>一级 |
| WMD-D05<br>跨通道操作反馈 | 退役/删除/恢复需分别反映各通道结果；证书未恢复时明确需重新注册，不以整体成功掩盖部分失败。 | 部分<br>一级 |

## 关键规则与边界

统一视图不是共享写聚合。通道权威数据独立，读模型滞后应显式呈现；关联依据与人工冲突处理规则需评审。

擦除与锁定必须经过权限和操作确认；不支持的 OS、版本、硬件或注册类型明确拒绝；macOS 动作见 WMD-MAC12。取消请求不能被展示成设备已撤销已完成操作。

## 验收场景

AC-D01-01　同一物理设备双通道关联后仅显示一条统一设备，同时可检查两套通道标识及状态；冲突不会误合并。

AC-D01-02　模拟一个通道失败和证书不可恢复，API/界面显示部分结果或 pending_reenroll 等等价状态，不错误声称可管理。

> 依据：[D02](../reference/historical-sources.md#d02) F-D、墓碑机制；[D04](../reference/historical-sources.md#d04)；[C14](../reference/historical-sources.md#c14)/C15/C22/C23/C24/C25。

---

# 06.3　F-D：数据采集、高级搜索与资产 API

*主要用户：管理员、服务台、资产集成系统。*

历史基础：MDM 采集模板、DDF 节点、基础 Agent 采集、搜索与保存查询已有。深度采集与动态 EA 不因读模型存在而自动获得。[C06](../reference/historical-sources.md#c06)[C19](../reference/historical-sources.md#c19)[C29](../reference/historical-sources.md#c29)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-Q01<br>标准资产采集 | 采集已承诺的硬件、OS、网络与软件/安全信息；字段带类型、来源及采集时间，不支持字段显示未知。 | 已有<br>一级 |
| WMD-Q02<br>采集模板 / 刷新 | 支持配置可读 CSP 模板、DDF 节点导入和按需刷新；展示排队/等待签入/部分结果，避免同步读取假象。 | 已有<br>一级 |
| WMD-Q03<br>组合搜索 | 支持字段发现、AND/OR 嵌套、类型匹配运算符、选列、排序和分页；合法字段以当前注册表为准。 | 已有<br>一级 |
| WMD-Q04<br>保存搜索 / 汇总 | 命名保存查询、版本冲突提示、删除与重用；提供设备状态、通道覆盖、OS 与合规汇总。 | 已有<br>一级 |
| WMD-Q05<br>外部获取资产 | 通过授权 API 获取资产与查询结果；保留机器可读数据消费，不实现 UI 导出或 CSV 导入导出。 | 已有基础<br>一级 |

## 关键规则与边界

搜索字段和嵌套深度以当前发布的字段注册表及已验证限制为准，不继承历史规划中的字段数量承诺。动态属性另见 WMD-X/WMD-COL。统一查询不能要求业务调用者自行选择操作系统，但原生字段与平台扩展仍可查询。

查询、智能组和报表应复用一致的字段定义与条件语义。字段不存在或权限不足时返回明确错误，不静默忽略条件。

## 验收场景

AC-Q01-01　选取数值、字符串、日期和 JSON 路径字段组成查询，验证排序/分页/选列及非法字段拒绝；保存并重放查询得到相同语义。

AC-Q01-02　设备不支持某 CSP 或未签入时，采集结果显示未知/部分/过期及原因，而非空值即成功或不合规。

> 依据：[D03](../reference/historical-sources.md#d03) 资产管理；[D04](../reference/historical-sources.md#d04)；[D05](../reference/historical-sources.md#d05) 028；[D13](../reference/historical-sources.md#d13)；[D15](../reference/historical-sources.md#d15)；[C01](../reference/historical-sources.md#c01)/C13/C19/C29。

---

# 06.4　F-G：静态分组、智能组与 Scope

*主要用户：MDM 管理员、安全管理员。*

历史基础：组业务、SQL 重算、成员 DIFF、事件消费与三元 Scope 均有实现。EA 条件仍依赖新属性管线。[C03](../reference/historical-sources.md#c03)[C10](../reference/historical-sources.md#c10)[C11](../reference/historical-sources.md#c11)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-G01<br>静态组 | 创建、编辑、删除及 API 批量管理成员；显示组的通道适用范围、成员与引用关系。 | 已有<br>一级 |
| WMD-G02<br>智能组 | 基于受支持字段定义条件、预览匹配结果并保存规则；支持设备属性变化触发与周期/手动重算。 | 已有<br>一级 |
| WMD-G03<br>成员差分与追踪 | 保留新增/移除成员、触发原因、耗时和失败记录；变化可驱动策略重新解析与补偿。 | 已有<br>一级 |
| WMD-G04<br>三元 Scope | 实际范围 = Target（目标并集）∩ Limitation（限制）− Exclusion（排除）；无限制组时不额外缩小范围。 | 已有<br>一级 |
| WMD-G05<br>EA / 跨平台分组 | 标准字段和扩展字段进入同一条件体系；Windows/macOS 混合组按统一 DeviceId 计数，执行按所选通道及设备/用户对象展开并去重。 | 规划扩展 <br>二级 |

## 关键规则与边界

组成员变化不得导致同一目标重复执行相同策略版本；离开范围只触发已声明的移除规则。删除被引用组须给出影响或阻止无提示破坏。

预览与正式重算需采用等价条件；数据未知或过期时的成员归属必须可解释，不能默认当真。

## 验收场景

AC-G01-01　构造目标、限制、排除三个集合，检查预览与正式执行对象完全符合公式；同一设备多重命中不重复。

AC-G01-02　设备属性变化后成员 DIFF、Scope 重算和新增执行链闭合；重复事件与重算失败不会静默丢失目标变更。

> 依据：[D02](../reference/historical-sources.md#d02) F-G；[D05](../reference/historical-sources.md#d05) 025/027；[C03](../reference/historical-sources.md#c03)/C10/C11/C12。

---

# 06.5　F-P：策略生命周期、执行与诊断

*主要用户：MDM 管理员、安全管理员。*

历史基础：策略、版本、激活/暂停/归档、逐设备执行及 PolicyReconciler 已存在。端到端追踪页面与更高层编排仍需补充。[C04](../reference/historical-sources.md#c04)[C12](../reference/historical-sources.md#c12)[C26](../reference/historical-sources.md#c26)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-P01<br>策略与版本 | 维护策略元数据、载荷、版本、作用域；发布版本可追溯，不通过直接修改已执行历史改变证据。 | 已有<br>一级 |
| WMD-P02<br>激活 / 暂停 / 中止 | 激活产生目标执行；暂停阻止后续适用调度；中止反映尚未完成任务的结果，不承诺撤销不可逆操作。 | 已有基础<br>一级 |
| WMD-P03<br>逐设备执行 | 展示策略版本、通道、执行/命令标识、当前阶段、结果码、时间和失败理由。 | 已有基础<br>一级 |
| WMD-P04<br>范围变化收敛 | 组、Scope、资源版本变化后计算期望与现有执行差异，补发或清理；过时结果不得错误覆盖新版本。 | 已有基础<br>一级 |
| WMD-P05<br>依赖 / 灰度 / 追踪 | 保留简单依赖编排、灰度推进/暂停及七步追踪的产品目标；统一展示定义到设备结果，缺失阶段明确未知。 | 规划<br>二级 |

## 关键规则与边界

统一追踪改为：定义 → 解析/预检 → 持久派发 → 等待终端 → 执行/原生处理 → 状态核实 → 汇总。Windows MDM 的 WNS/SyncML/CSP、Apple 的 APNs/MDM/DDM、Agent 的领取/执行作为可展开的明细，不能把 WNS 步骤套用于所有平台。[E06](../reference/external-sources.md#e06)[E17](../reference/external-sources.md#e17)

执行成功须与相应命令结果关联；合规还需实际状态/规则证据。自动重试只适用于已定义的可重试失败，不能对所有副作用无差别重放。

## 验收场景

AC-P01-01　激活一个版本后，目标设备能追到对应命令与结果；每一步失败均可定位，未签入设备保持等待状态。

AC-P01-02　策略暂停、范围移除、资源变更、重复结果与过时回执场景下，执行终态和界面解释与真实效果一致。

> 依据：[D02](../reference/historical-sources.md#d02) F-P；[D04](../reference/historical-sources.md#d04) 019/022；[D05](../reference/historical-sources.md#d05) 七步追踪；[D06](../reference/historical-sources.md#d06)；[C04](../reference/historical-sources.md#c04)/C12/C13/C26。

---

# 06.6　F-P：Windows CSP、OMA-URI 与原生配置

*主要用户：MDM 管理员、配置模板维护者。*

本模块仅定义 Windows 平台适配；macOS Profile/DDM 见 WMD-MAC，统一入口见 WMD-V。

历史基础：专用 Provider、OMA-URI Profile 与 csp_config 并存；不是已经完成“唯一通用执行模型”的迁移。[C08](../reference/historical-sources.md#c08)[C09](../reference/historical-sources.md#c09)[C26](../reference/historical-sources.md#c26)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-C01<br>通用配置清单 | 支持 syncml_manifest/v1 描述 Get/Add/Replace/Delete/Exec 等受支持命令，包含目标 URI、格式、值及 cleanup。 | 已有<br>一级 |
| WMD-C02<br>保存前验证 | 结构错误阻止保存/发布；提供 DDF 查询与验证预览，区分格式错误、未知 URI、操作能力告警。 | 已有<br>一级 |
| WMD-C03<br>基础管理配置 | 保留密码、WiFi、BitLocker、证书、Defender、USB、防火墙、VPN、重启和诊断等现有配置入口及结果。 | 已有基础<br>一级 |
| WMD-C04<br>配置清理 | 策略中止或退出范围时按明确 cleanup/删除语义执行；不支持删除/回滚的节点必须解释限制。 | 已有基础<br>一级 |
| WMD-C05<br>企业配置模板 | 将 Hello、WDAC/AppLocker、Kiosk、电源、代理、隐私/数据保护与安全基线作为后续可用配置模板/产品包。 | 规划<br>二级 |

## 关键规则与边界

历史 DDF 对能力不匹配和未知节点主要给出 warning，迁移时必须明确校验强度。严格校验模式、未登记节点准入与受支持设备矩阵为待决策项。

历史裁剪建议 [D14](../reference/historical-sources.md#d14) 提出：可减少纯“配置翻译型”专用 Provider，但软件、凭证、更新环的业务对象和结果链仍必须保留。旧策略兼容与迁移另行验收。

## 验收场景

AC-C01-01　合法清单准确生成命令，非法 schema/操作/格式被明确拒绝；未知 URI 和不匹配操作能看到告警。

AC-C01-02　配置应用与 cleanup 分别在支持的真实 Windows 版本验证；不能以“可构造命令”替代“节点被设备支持”。

> 依据：[D04](../reference/historical-sources.md#d04)；[D05](../reference/historical-sources.md#d05) 027；[D07](../reference/historical-sources.md#d07)；[D14](../reference/historical-sources.md#d14)；[C08](../reference/historical-sources.md#c08)/C09/C26/C30。

---

# 06.7　F-S：资源与软件全生命周期

*主要用户：软件管理员、MDM 管理员、服务台。*

历史基础：资源和版本管理已有；应用定义、检测、安装状态、卸载与灰度编排尚不能从 Resource 或 CSP 能力推导为完成。[C21](../reference/historical-sources.md#c21)[D05](../reference/historical-sources.md#d05)[D08](../reference/historical-sources.md#d08)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-S01<br>资源与包 | 维护文件、版本、元数据、上传下载及引用；下载授权、完整性校验与包来源可追踪。 | 已有基础<br>一级 |
| WMD-S02<br>跨平台应用定义 / 分配 | 一个逻辑应用关联 Windows/macOS 的版本、架构、原生包或包管理器实现；管理者选择应用与 Scope，不手工拆两条业务。每个实现声明通道、检测、升级和卸载支持。 | 规划扩展 <br>二级 |
| WMD-S03<br>MDM 安装 | 完成 MDM 应用安装能力，形成安装命令、状态核实、失败诊断与管理页面闭环。 | 规划<br>一级 |
| WMD-S04<br>Agent 安装 / 卸载 | 下载与续传 → 哈希/签名验证 → 安装 → 检测 → 结构化结果；支持显式卸载及失败恢复。 | 规划<br>二级 |
| WMD-S05<br>依赖与分阶段 | 支持依赖校验、顺序执行、分批推进/暂停，逐设备展示 downloading/installing/installed/failed 等状态。 | 规划<br>二级 |
| WMD-S06<br>WinGet 私有源管理 | 提升为正式二级软件能力：源注册/托管发布、包审批、版本、分配、安装/升级/卸载/固定及验证；由 Agent 的 WinGet 执行器承担。详见 WMD-REP，不再作为第三交付通道。 | 规划升级 <br>二级 |

新增 Homebrew 私有 Tap、Bottle/Cask 产物管理，详见 WMD-BRW。软件管理对象统一，包格式与原生命令不强行统一。

## 关键规则与边界

MSI 不按包格式预设通道独占；正式支持矩阵按包类型、CSP/执行器与设备版本验收。

同一逻辑应用的变更默认仅一个写通道；MDM-only 不自动具有 WinGet/Brew 执行能力。Scope 退出自动卸载必须在应用策略中显式启用；不可逆安装脚本不能承诺通用自动回滚。缺依赖、包损坏或下载 URL 过期均需明确失败。

## 验收场景

AC-S01-01　对选定的一种 MDM 应用和一种 Agent 应用，分别验证安装、检测、版本升级、失败以及卸载，能追踪至每台设备。

AC-S01-02　离线、断点续传、重复任务、错误签名、依赖环和分批阈值不满足时不继续危险部署，管理员可诊断和恢复。

> 依据：[D02](../reference/historical-sources.md#d02) F-S；[D05](../reference/historical-sources.md#d05) 032；[D07](../reference/historical-sources.md#d07) P7.3；[D08](../reference/historical-sources.md#d08) Agent C/D；[C21](../reference/historical-sources.md#c21)。

---

# 06.8　F-R：Agent 任务与远程脚本

*主要用户：桌面支持、运维自动化管理员。*

历史基础：存在服务端领取/ack、客户端校验、SQLite 队列组件，但真实 Agent 不执行已领取任务。该模块是后续脚本与软件能力的先决条件。[C05](../reference/historical-sources.md#c05)、[C06](../reference/historical-sources.md#c06)、[C07](../reference/historical-sources.md#c07)[C28](../reference/historical-sources.md#c28)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-R01<br>任务生产与领取 | 管理员手动或策略触发创建持久任务；按目标设备授权领取，保留 taskId、类型、版本、有效期及执行状态。 | 部分<br>一级 |
| WMD-R02<br>跨平台可信脚本执行 | Windows 使用受支持 PowerShell，macOS 使用已声明的 shell/解释器；同一脚本任务可绑定平台变体。任务签名、参数校验、权限、超时、进程树清理与输出结构共用；noop 仅作诊断。 | 规划扩展 <br>一级 |
| WMD-R03<br>结构化结果 | 回传并展示 exitCode、stdout、stderr、durationMs、executedAt 与失败分类；输出限量并保护敏感信息。 | 部分<br>一级 |
| WMD-R04<br>离线与幂等 | 结果网络失败写入本地持久队列，重连补传；重复领取/回执不造成同一任务无控制重复执行。 | 部分<br>一级 |
| WMD-R05<br>脚本库与调度 | 维护脚本、版本、参数、支持 OS 与历史执行；支持手动、签入/注册或计划触发及策略关联。 | 规划<br>二级 |

## 关键规则与边界

任务确认与执行结果的契约必须区分“收到命令”和“完成执行”，兼容接口不能各自定义相互矛盾的成功状态。

脚本超时和重试预算须显式配置；是否重试取决于任务副作用，不对任意脚本承诺安全重放。终端授权与签名不可省略。

## 验收场景

AC-R01-01　手动创建签名任务 → 真 Agent 领取 → 执行 → 输出持久化 → API/控制台可见，不能由模拟客户端代替。

AC-R01-02　签名错误不执行；超时能结束进程树；结果上报中断后补传；重复回执不使终态反复变化或重复副作用。

> 依据：[D05](../reference/historical-sources.md#d05) 029；[D08](../reference/historical-sources.md#d08) Agent A；[D12](../reference/historical-sources.md#d12)；[C05](../reference/historical-sources.md#c05)/C06/C07/C28。

---

# 06.9　F-EA：扩展属性与深度采集

*主要用户：资产管理员、安全管理员、自动化开发者。*

历史基础：可配置 CSP 采集与原始结果已有，但不存在完整统一 EA 定义、值、投影与规则联动链。[C14](../reference/historical-sources.md#c14)[C29](../reference/historical-sources.md#c29)[D12](../reference/historical-sources.md#d12)[D13](../reference/historical-sources.md#d13)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-X01<br>统一扩展字段定义 | 定义稳定键、类型、单位、敏感等级、来源权威、有效期与适用范围；支持标量、受限数组和结构化路径。数据字典统一供搜索、智能组、合规和 UI 消费，详见 WMD-COL。 | 规划扩展 <br>一级 |
| WMD-X02<br>Manual 属性 | 管理员或授权 API 为设备写入属性值，记录来源、修改者、时间与审计。 | 规划<br>二级 |
| WMD-X03<br>MDM 来源属性 | Windows 以受支持 CSP Get 映射，macOS 以原生命令响应或 DDM 状态映射到扩展字段；无对应原生信息的字段标记不支持，不将自定义字段声明误当成设备会自动产生该数据。 | 目标明确 <br>二级 |
| WMD-X04<br>Script 属性 | 依赖 WMD-R，绑定脚本版本执行并转换结果；失败、未知与旧值必须区分。 | 规划<br>二级 |
| WMD-X05<br>查询与策略联动 | EA 更新后进入设备详情、搜索字段与智能组；触发成员变化及后续策略，沿用统一条件语义。 | 规划<br>二级 |

## 关键规则与边界

MDM Get 可读属性不是任意脚本运行能力；Exec 也不等同于 PowerShell。先交付 MDM-first 不能对外称 Script EA 已完成。[D13](../reference/historical-sources.md#d13)

采集来源为：Agent 内置采集、Agent/osquery、Agent/自定义脚本、MDM；Manual/API 保留为管理赋值方式，不算第三设备采集通道。LDAP 不自动纳入。osquery 输出映射按 WMD-COL 实现。

## 验收场景

AC-X01-01　Manual 或 MDM 属性更新后，详情、搜索、智能组三处值及类型一致；非法类型不污染旧值。

AC-X01-02　Script EA 从真实执行产生值，再驱动分组与策略；脚本失败、数据过期与设备离线都能被区分。

> 依据：[D05](../reference/historical-sources.md#d05) 030；[D08](../reference/historical-sources.md#d08) Agent B；[D12](../reference/historical-sources.md#d12)/D13；[C14](../reference/historical-sources.md#c14)/C29。

---

# 06.10　F-M：合规、漂移与修复

*主要用户：安全管理员、审计人员。*

历史基础：已有安全采集、命令结果、合规快照和查询基础；规则化评估、自动修复与访问限制仍是产品增强。[C01](../reference/historical-sources.md#c01)[C13](../reference/historical-sources.md#c13)[C14](../reference/historical-sources.md#c14)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-H01<br>当前与历史合规 | 提供当前状态、策略执行证据及时间范围内历史；标明采集/评估时间，区分 unknown、pending 与明确不合规。 | 已有基础<br>一级 |
| WMD-H02<br>规则与宽限期 | 支持基于受控资产/安全字段定义规则、严重性、宽限期及原因；未知数据不可直接判定合规。 | 规划<br>二级 |
| WMD-H03<br>漂移检测 / 修复 | 比对期望设置与观察状态；按授权策略告警或修复，保留修复前后证据和失败原因。 | 规划<br>二级 |
| WMD-H04<br>合规反馈集成 | 合规变化进入智能组、Webhook/查询接口；向外部准入系统提供状态、原因及新鲜度。 | 规划<br>二级 |
| WMD-H05<br>基线模板 / 证明 | 保留安全基线模板、健康证明/DHA/TPM 信号与规则结合；标准映射与证明验证需独立验收。 | 规划<br>三级 |

## 关键规则与边界

CSP 返回成功只能证明相应命令的结果，不能替代所有受控设置的当前值与合规评估。读不到、不支持、超时和真正不合规要分别呈现。

合规标准适配属于目标要求，不代表已取得认证或合规结论。模板标准、版本和许可/审查责任待定。

## 验收场景

AC-H01-01　配置应用后再次读取对应状态；人为改变受控项可识别漂移并按策略修复，保留完整时间线。

AC-H01-02　缺失/过期数据、宽限期未结束、证据验证失败都不显示为已通过；历史结果能定位对应规则版本。

> 依据：[D04](../reference/historical-sources.md#d04) 019–022；[D05](../reference/historical-sources.md#d05)；[D06](../reference/historical-sources.md#d06) §8；[D07](../reference/historical-sources.md#d07) P8；[C01](../reference/historical-sources.md#c01)/C13/C14。

---

# 06.11　安全能力：LAPS 与 BitLocker 密钥托管

*主要用户：安全管理员、受授权服务台。*

macOS 的 FileVault PRK、Bootstrap Token、Recovery Lock 复用敏感材料访问控制，但各有独立语义与前提，见 WMD-MAC08/09；不重命名为 BitLocker 或 Windows LAPS。

历史基础：存在 BitLocker 配置/状态能力，但当前资料不足以证明凭证托管、密钥查阅与轮换闭环。[D05](../reference/historical-sources.md#d05)[C08](../reference/historical-sources.md#c08)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-K01<br>LAPS 策略与轮换 | 配置本地管理员密码策略、轮换周期和目标；支持自动/手动轮换并核实新凭证状态。 | 规划<br>二级 |
| WMD-K02<br>恢复密钥托管 | 收集并加密保管 BitLocker 恢复材料，关联设备、卷/驱动器、密钥标识和时间；支持多盘。 | 规划<br>二级 |
| WMD-K03<br>特权查阅 | 凭证只能由明确授权角色查看，记录谁在何时因何查看哪台设备的何种密钥；不得混入一般资产 API。 | 规划<br>二级 |
| WMD-K04<br>密钥安全与恢复 | 密文存储、传输保护、密钥管理、轮换与备份恢复一并设计；日志/事件/错误信息不得泄露明文。 | 规划<br>二级 |
| WMD-K05<br>用户自助查看 | 原始需求提出用户查看自身恢复密钥；与后续特权角色访问定义不同，保留为待决策，不默认开放。 | 待决策<br>三级 |

## 关键规则与边界

pgcrypto 是 D05 的明确方案选择；D02/D06 另有 AES-GCM/KeyVault 类描述。本 PRD 冻结“受控加密托管与访问证据”，算法/密钥设施冲突见决策表，不静默替换。

读取/回传路径、OS 版本、账户/卷限制须以选定协议和真实设备验收；不能因 URI 可以配置就认定恢复材料一定可取回。

## 验收场景

AC-K01-01　对试点支持矩阵验证配置 → 轮换/生成 → 安全收集 → 授权查阅 → 审计；旧/新凭证和卷不混淆。

AC-K01-02　无权者、注销会话及跨设备非法请求不能读密钥；备份恢复后可按授权取得正确材料，日志无明文。

> 依据：[D03](../reference/historical-sources.md#d03) 磁盘加密；[D02](../reference/historical-sources.md#d02) F-P05/安全；[D05](../reference/historical-sources.md#d05) 026；[D06](../reference/historical-sources.md#d06)；[D07](../reference/historical-sources.md#d07) P7.4。

---

# 06.12　F-P：Windows 更新环与补丁状态

*主要用户：安全管理员、终端运维管理员。*

本模块保留 Windows 更新环；跨平台更新活动共享 Scope、维护窗口与进度视图，macOS 发布与状态详见 WMD-MAC13。

历史基础：更新相关 CSP/设备动作不能等同于更新环业务。D05 明确 033 后置，依赖 025 智能组，不依赖 026。[D05](../reference/historical-sources.md#d05)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-U01<br>更新环管理 | 维护 Preview/Pilot/Production 或等价分组阶段，配置延迟、截止日期、通知和维护窗口。 | 规划<br>二级 |
| WMD-U02<br>组绑定与发布 | 每环关联智能组，解析目标并生成受支持更新配置；提供暂停/恢复质量更新与功能更新。 | 规划<br>二级 |
| WMD-U03<br>更新状态与报告 | 按设备/环统计已更新、待更新、失败和未知；显示更新标识、最近评估和失败原因。 | 规划<br>二级 |
| WMD-U04<br>评估与进阶编排 | Agent 采集已安装 KB/待更新信息；更细发布推进、WSUS 集成和用户交互按单独支持矩阵扩展。 | 规划<br>三级 |

## 关键规则与边界

更新环的延迟天数须可配置，不应硬编码为单一方案；环重叠时优先级与冲突处理须在实施前定稿。

“策略已下发”“设备已扫描”“更新已下载”“已安装/待重启”属于不同事实。不能只靠设置 CSP 成功推导补丁合规。

## 验收场景

AC-U01-01　同一更新在试点环先执行，后续环按配置延迟；暂停期间不推进新的发布，恢复行为可解释。

AC-U01-02　设备离线、等待重启、安装失败和没有评估数据时，在逐设备和汇总报表中口径一致。

> 依据：[D03](../reference/historical-sources.md#d03) Windows 持续更新；[D05](../reference/historical-sources.md#d05) 033；[D07](../reference/historical-sources.md#d07) P7/P9；[D08](../reference/historical-sources.md#d08) Agent D。

---

# 06.13　F-A：账户、SSO、会话与权限

当前接入边界见 [#2437 修订的认证指南](../guides/202609091600-2343-mdm-identity.md)：首期单租户、持久化四类主体授权、真实资产查询与危险动作授权拒绝。规则、用户组启停及成员由受保护 API 管理；操作与资源范围成对匹配、并集生效、默认拒绝，详见 [#2363 授权指南](../guides/202609200002-2363-authorization.md)。危险动作有权时仍返回不支持，不表示命令执行已交付；管理员注册许可与持久审计见 [F02 指南](../guides/202609090001-2347-enrollment-audit.md)：统一 Enrollment 创建/恢复/取消与独立凭据撤销，授权、签发意图及原子绑定形成闭环，查询/拒绝审计失败不放行。[Windows 接入](../guides/202609111146-2350-windows-enrollment-management.md) 覆盖 HTTPS Discovery/XCEP/WSTEP、mTLS 与首次 SyncML 认证初始化；pending 不代表完成，T1/T2 证据由 #2350/#2351 单 PR 绑定，Windows T3 独立验收。

*主要用户：系统管理员、安全管理员、集成系统。*

历史基础：本地账户、SSO/JIT/组角色映射、RBAC 及内部主体校验已存在；MFA 和 M2M 仍需确定产品闭环。[C01](../reference/historical-sources.md#c01)[C17](../reference/historical-sources.md#c17)[C18](../reference/historical-sources.md#c18)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-A01<br>本地身份 / 会话 | 本地认证、用户管理、禁用及权威会话由内嵌 Identity 四个公开组件持有；MDM 持有实例/租户、装配、秘密和产品授权，每请求重新权威验证。沿用组件 cookie、刷新和退出接口，本地身份不依赖 AD、中央服务或 IdP。 | 已有<br>一级 |
| WMD-A02<br>OIDC SSO / 映射 | 可选 IdP 配置、SSO/JIT、显式身份关联与 step-up 由 Identity 公开组件持有，callback 属于产品；MDM 持有产品授权规则与设备范围。用户按 instance/tenant/principal 精确匹配；安全组与完整部门树使用 Identity 验证的 provider/issuer/configurationVersion 来源和独立期限，部门规则显式选择 exact/subtree；外部 subject 不按邮箱或显示名自动关联。 | 已有<br>一级 |
| WMD-A03<br>主体授权与危险权限 | 持久化用户、IdP 安全组、部门及本地显式用户组四类规则；每项 grant 绑定 operation/scope。危险动作、凭据与软件发布均显式授权。旧五角色、静态 Binding 和 allow_* API 删除，不提供兼容读写。Identity 账户/provider 管理保留独立配置。 | #2363<br>一级 |
| WMD-A04<br>管理员 MFA | 为商用管理面确定 MFA 实现与恢复方案，可依托选定 IdP；本地应急账户的使用及审计规则须明确。 | 规划<br>二级 |
| WMD-A05<br>M2M / 多租户 SSO | 人类会话与 M2M client_credentials 分离；多 IdP 配置不等同 MSP 数据隔离，多租户产品范围须另立项。 | 规划<br>三级 |

## 关键规则与边界

历史五角色和 RBAC 路由只保留为来源参考，不构成当前 API 承诺或隐式特权。每请求读取当前规则与本地用户组一致快照；组停用、成员移除和规则撤销在新请求生效，来源期限在每次使用时复核，Windows 续接/最终绑定与延迟发布重新授权。初始化只显式执行一次；删除后的 tombstone 和历史回执不会恢复权限。SSO 组/部门变化、账户禁用与会话注销需作为行为验收。

多 IdP 配置与组织/租户隔离分别建模和验证；支持多个 IdP 不代表已经具备多租户数据隔离。

## 验收场景

AC-A01-01　四类主体的操作/范围授权分别影响设备与管理接口；规则并集不交叉扩大权限，未授权及跨来源/跨实例/跨租户请求拒绝且无业务副作用。规则与成员 CAS、组启停、撤销、墓碑及幂等重放行为可解释并有审计；Identity 管理权限独立验证。

AC-A01-02　可信安全组及部门 exact/subtree 影响产品权限；来源缺失、非法或过期只移除对应授权，独立用户/本地组授权继续独立判定。禁用/删除账户、无效 token 与注销会话不能继续通过受保护入口；上游变化按公开快照期限验收，不宣称实时获知撤组。

> 依据：[D02](../reference/historical-sources.md#d02) F-A/认证；[D05](../reference/historical-sources.md#d05)；[D06](../reference/historical-sources.md#d06) 权限增强；[D08](../reference/historical-sources.md#d08) B4；[C01](../reference/historical-sources.md#c01)/C17/C18。

---

# 06.14　F-M：审计、报告与运营诊断

*主要用户：审计人员、IT 经理、部署运维。*

历史基础：审计查询、Dashboard 与部分指标已有；审计服务仍明确存在 best-effort / dropped 路径。不可称为取证级不可丢失。[C01](../reference/historical-sources.md#c01)[C16](../reference/historical-sources.md#c16)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-M01<br>关键管理审计 | 记录主体、目标、动作、时间、结果、关联标识；覆盖身份/组/策略/设备动作/配置/密钥访问。 | 部分<br>一级 |
| WMD-M02<br>持久化与失败可见 | 关键操作的审计持久化或可靠待投递须有保证；落库/磁盘故障不能仅静默丢弃，恢复可追踪。 | 部分<br>一级 |
| WMD-M03<br>报告与指标 | 提供资产、部署、合规趋势、证书到期与更新状态等 API 报告，定义统计分母与时间口径。 | 部分<br>二级 |
| WMD-M04<br>全链路诊断 | 从设备/策略跳转到队列、执行、失败、重试与 WNS 状态；显示降级及读模型延迟。 | 部分<br>二级 |
| WMD-M05<br>告警 / 保留策略 | 为积压、重复失败、证书到期、审计故障与恢复异常建立告警、责任人和保留/清理规则。 | 规划<br>二级 |
| WMD-M06<br>遥测与分析 | 保留 CPU/内存/磁盘/SMART、软件使用分析和趋势；时序深度、频率、留存及用户可见性按需扩展。 | 规划<br>三级 |

## 关键规则与边界

运维日志与管理审计分开。指标计数增长并不能证明一条具体关键审计已经持久化；仅存在文件溢写也不能保证无损和防篡改。

报告只走授权 API 与控制台展示，不追加 CSV/Excel 导出。定时报告如继续立项，输出方式必须服从排除项。

## 验收场景

AC-M01-01　模拟审计 DB 暂不可用及溢写失败：关键操作按已批准的失败策略处理，故障可见，恢复后记录可关联且不伪造成功。

AC-M01-02　从相同数据集比对资产数、合规率、通道覆盖和部署结果，详情与汇总一致，未知设备不混入已合规。

> 依据：[D02](../reference/historical-sources.md#d02) F-M/非功能；[D05](../reference/historical-sources.md#d05)；[D07](../reference/historical-sources.md#d07) 报告；[D08](../reference/historical-sources.md#d08) B5/E3；[D10](../reference/historical-sources.md#d10)；[C01](../reference/historical-sources.md#c01)/C16。

---

# 06.15　外部系统集成与 Webhook

*主要用户：企业集成开发者、资产与安全平台。*

历史基础：已有管理 API 与内部事件基础；不代表 Webhook 产品配置、投递、重试、权限和运营能力已完成。[D05](../reference/historical-sources.md#d05)[D08](../reference/historical-sources.md#d08)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-I01<br>Webhook 配置 | 维护目标地址、认证、事件类型与组过滤、启停和测试投递；凭据按敏感配置管理。 | 规划<br>二级 |
| WMD-I02<br>可靠投递 | 事件进入持久投递记录，指数退避、失败终态和人工重试可见；事件有稳定标识，便于接收端去重。 | 规划<br>二级 |
| WMD-I03<br>合规 / ITSM 集成 | 通过查询或事件输出设备、组、策略、执行和合规变化；只暴露已承诺字段与权限范围。 | 规划<br>二级 |
| WMD-I04<br>证书 / 生态扩展 | SCEP、外部 PKI、SDK、Terraform 等作为后续集成包；外部协议和运维责任单独定义。 | 规划<br>三级 |

## 关键规则与边界

D05 描述重试 1/2/4 秒、最多 3 次、最近 100 条投递记录，属于原草案参数；业务保留期与补偿要求需评审，不能以仅保留 100 条替代审计留存。

Webhook 目标地址需防止访问不允许的内部目标，日志不回显认证材料，失败投递不应阻塞设备管理主交易。

## 验收场景

AC-I01-01　配置测试事件与真实事件均能准确过滤和投递；重复通知可凭 eventId 去重，失败原因、重试次数与最后结果可查询。

AC-I01-02　无权限的外部主体不可读取资产/合规/执行信息；凭据轮换后旧凭据按约定失效，生产故障不造成事件无声丢失。

> 依据：[D03](../reference/historical-sources.md#d03) 外部系统；[D05](../reference/historical-sources.md#d05) 031/Phase 3；[D06](../reference/historical-sources.md#d06)；[D07](../reference/historical-sources.md#d07) P8/P9；[D08](../reference/historical-sources.md#d08)。

---

# 06.16　平台设置、部署与运行保障

*主要用户：部署运维、平台管理员。*

历史基础：Setup、配置 API、基础设施测试、日志配置及 WNS 重载已在代码中；仍须核实“已保存”和“已生效”的一致性。[C01](../reference/historical-sources.md#c01)[C02](../reference/historical-sources.md#c02)[C20](../reference/historical-sources.md#c20)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-O01<br>配置生效反馈 | 设置保存后返回版本与生效方式；即刻生效、定期重载、需重启三类行为明确显示。 | 已有基础<br>一级 |
| WMD-O02<br>基础设施与健康 | 测试 DB/Redis/对象存储连接，启动时核验必要依赖；区分进程存活、服务就绪与业务降级。 | 已有基础<br>一级 |
| WMD-O03<br>故障恢复 / 升级 | 定义备份恢复、schema/应用兼容、升级失败处理与回退条件；恢复后命令、投影、证书和审计语义正确。 | 部分<br>二级 |
| WMD-O04<br>部署支持包 | 提供企业本地部署与运行说明，区分已有 Compose 路径和未来 HA/集群；TLS 入口、域名与证书要求一致。 | 已有 / 规划<br>二级 |

## 关键规则与边界

WNS 凭据检查须明确实际刷新周期，不能将所有设置展示为即时生效。日志级别与日志格式/MDM debug 的生效策略也须分别呈现。

产品自身部署、迁移执行、进程装配、生产运维和 T3 由 MDM 产品仓负责；RSS 只提供约定的通用机制，不能由库发布代替产品运维交付。[范围规则](../rules/project-scope.md)

## 验收场景

AC-O01-01　修改 WNS、日志级别和基础设施参数，逐项检查实际运行状态、重启提示及失败回滚/保留旧值行为。

AC-O01-02　演练进程重启、数据库短暂故障和版本升级失败，确认已承诺的持久任务、审计和管理身份没有被静默重置。

> 依据：[D01](../reference/historical-sources.md#d01)；[D02](../reference/historical-sources.md#d02) 非功能；[D16](../reference/historical-sources.md#d16)；[范围规则](../rules/project-scope.md)；[C01](../reference/historical-sources.md#c01)/C02/C20。

---

# 06.17　WMD-V：跨平台虚拟执行层

目标：一套产品对象与调用契约，两类交付通道，按能力选择平台实现。历史代码仅预留 macOS 平台枚举；没有该完整闭环。[C32](../reference/historical-sources.md#c32)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-V01<br>统一设备与能力模型 | DeviceId 统一关联独立 Enrollment；能力按 OS/版本/架构、Agent/MDM 状态、执行身份、授权和原生前提计算，输出 supported/unsupported/blocked/unknown 及原因。 | 新增目标<br>一级 |
| WMD-V02<br>前后端与 Agent 共用业务契约 | 统一定义 Operation、Target、DesiredState、CollectionRequest、ExecutionReceipt 与 Observation；控制台、服务端和 Agent 共享版本化 schema/SDK，原生 MDM 报文经适配器转换。 | 新增目标<br>一级 |
| WMD-V03<br>逻辑意图与平台实现分离 | 提供 inventory.collect、configuration.apply、software.ensure、script.run、device.action 等操作族；模板绑定平台变体与校验器，禁止以任意 shell 字符串作为全部能力的统一抽象。 | 新增目标<br>一级 |
| WMD-V04<br>适用性与前置条件 | 发布前计算 OS、版本、芯片、设备/用户上下文、解释器、包管理器、证书/监督状态等前提；不适用与暂时阻塞分开。 | 新增目标<br>一级 |
| WMD-V05<br>计划预览与冻结 | 计划预览展示支持/不支持/阻塞设备、选定通道/执行器、权限、包/脚本/模板版本及风险。批准后冻结策略 generation 与产物摘要；派发前再次检查关键前提。 | 新增目标<br>一级 |
| WMD-V06<br>统一结果与原生明细 | 公共结果至少区分受理、等待、执行、等待用户、等待重启、结果不明、失败、状态已核实；保留原生状态码、命令 UUID、通道与证据强度。 | 新增目标<br>一级 |
| WMD-V07<br>重复投递与执行恢复 | 业务执行标识稳定；Agent 有持久执行日志与结果补传。native MDM 无法共享本地幂等存储时按命令语义和状态核实恢复，不宣称任意动作 exactly-once。 | 新增目标<br>一级 |
| WMD-V08<br>可信任务与回执 | 任务绑定设备、注册世代、用途、摘要、过期时间和授权；回执由实际通道认证入口产生并归属原任务。Agent 自报 capability 不得绕过服务端授权。 | 新增目标<br>一级 |
| WMD-V09<br>版本取代与有界取消 | 新 generation 取代旧期望；已在端上执行的旧命令不能假设可召回。服务端拒绝旧结果覆盖新态，并安排读后核实和必要补偿。 | 新增目标<br>一级 |
| WMD-V10<br>采集与变更权限分离 | 采集计划与变更计划共用调度和结果关联，但使用不同操作类型、预算和权限。采集脚本标注只读意图仍按代码执行风险审批。 | 新增目标<br>一级 |
| WMD-V11<br>开放边界与原生扩展 | 标准字段覆盖共同语义；windows.*、macos.* 等命名空间保留原生类型和限制。扩展模板可复用现有调度，不新建万能虚拟机或动态插件平台。 | 新增目标<br>二级 |
| WMD-V12<br>协议兼容与外部消费 | 共享契约支持显式版本协商；服务端遇到旧 Agent 不支持的操作返回不支持或选择获准兼容模板。旧 Windows API 通过版本化迁移保留承诺。 | 新增目标<br>一级 |

## 关键规则与边界

“虚拟执行层”在本文中指业务执行抽象，不是虚拟机。业务调用者无需为每次管理操作专门区分操作系统；模板维护者和适配器仍必须处理差异。标准字段可以跨 OS 共用；BitLocker 恢复项、FileVault 令牌、CSP URI、Apple Payload 等不得抹平成失去约束的 JSON。

建议的自底向上结构为：RSS 已接纳的事务消息/持久执行机制 → 产品通道适配器与客户端执行器 → 能力解析和计划生成 → 设备/策略/采集/软件业务 → 统一 API 与控制台。共享 schema 是产品契约，不强制所有层链接同一个大 crate；Apple/Windows 系统自带 MDM 客户端不可能直接采用自研 Agent 的网络协议。[范围规则](../rules/project-scope.md)

协议示意，不冻结 URL 或语言：

```json
{
  "operation": "inventory.collect",
  "target": {"group_id": "managed-desktops"},
  "template_ref": "asset-baseline@3",
  "channel_policy": {"mode": "auto", "allowed": ["agent", "mdm"]},
  "idempotency_key": "request-uuid"
}
```

接口缺省无需携带 os。计划响应包含每台设备的 selected_channel、executor、resolved_version、blocked_reason 与 verification_plan。原生 API 作为高级入口必须复用相同授权、范围、审计和排队机制，不能绕过统一执行记录。

## 验收场景

AC-06-17-01　对同一 Windows/macOS 混合组调用同一 inventory.collect；同一字段分别由可用采集器产生，调用者不分 OS。

AC-06-17-02　对同一组提交“确保企业工具已安装”；计划分别选择 WinGet、Brew 或已批准原生包实现，不能只修改平台字段后发送相同原始载荷。

AC-06-17-03　设备缺少前提、任务过期、权限撤销、旧结果晚到分别验证；不支持的能力在派发前可见。

---

# 06.18　WMD-MAC：macOS 管理能力

macOS 是正式产品目标。现有归档仅有 PlatformMacOS 预留值与 mock 测试，不能认定已经具备 macOS MDM 或 Agent。[C32](../reference/historical-sources.md#c32)

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-MAC01<br>Apple 管理基础设施 | 管理 APNs topic/证书/私钥、CSR 签名来源、TLS、设备身份 CA/SCEP、到期告警与轮换；不同证书用途分开。生产签名资质或服务来源为上线前置条件。 | 新增目标<br>一级 |
| WMD-MAC02<br>macOS 手动注册 | 提供受控注册入口与签名 enrollment profile、设备认证、Check-in/TokenUpdate/CheckOut 处理；区分设备/用户 Enrollment、管理授权状态及重注册。 | 新增目标<br>一级 |
| WMD-MAC03<br>ABM/ADE 自动注册 | 对接组织的 Apple 设备分配/ADE 服务，管理 token、序列号同步、注册配置与 Setup Assistant 阶段；自动化注册不依赖 CSV。 | 新增目标<br>二级 |
| WMD-MAC04<br>配置描述文件 | 提供密码、Wi-Fi、VPN、证书、限制等已选定 payload 的模板/上传、版本、Scope、安装、移除与结果；识别设备/用户级作用域。 | 新增目标<br>一级 |
| WMD-MAC05<br>声明式设备管理 DDM | 管理声明标识/版本、配置/激活/资产、声明集合与状态报告；支持期望状态与实际状态比较、退役/移除以及旧 profile 共存冲突检查。 | 新增目标<br>二级 |
| WMD-MAC06<br>原生资产与安全清单 | 按原生 DeviceInformation、SecurityInfo、应用/profile 清单及已支持 DDM 状态映射统一字段；保留缺失/受限/过期，不声称能采任意路径或脚本输出。 | 新增目标<br>一级 |
| WMD-MAC07<br>隐私权限与系统能力配置 | 管理所需 PPPC、系统扩展、后台项等模板，绑定应用签名身份与版本前提；区分允许管理、需要用户批准与不可自动授予。 | 新增目标<br>二级 |
| WMD-MAC08<br>FileVault 管理与 PRK 托管 | 提供 FileVault 期望、启用/延期进度、个人恢复密钥托管、授权查询与轮换验证；已加密与密钥已安全托管分别显示。 | 新增目标<br>二级 |
| WMD-MAC09<br>Bootstrap Token 与恢复访问保护 | 独立维护 Bootstrap Token 托管状态及支持设备的 Recovery Lock；Secure Token、volume ownership 只采集/解释可获信号，不承诺任意远程生成或转移。 | 新增目标<br>二级 |
| WMD-MAC10<br>原生软件与 Apple 应用分配 | MDM 包部署先完成受支持签名 PKG；按独立能力接入 Apps and Books/VPP 许可、分配/回收和托管应用状态。DMG/任意脚本不假定属于原生安装命令。 | 新增目标<br>二级 |
| WMD-MAC11<br>macOS Agent 交付 | 提供签名/公证的安装产物、受控 launchd 服务、设备独立注册、共享任务协议、osquery/脚本/Brew 执行器、更新和卸载；按架构独立验证。 | 新增目标<br>一级 |
| WMD-MAC12<br>远程动作与危险操作 | 按硬件/OS/注册前提开放重启、锁定、擦除等动作；单独危险权限和确认，记录不可逆性。不得照搬 iOS 丢失模式或 Windows 专有动作。 | 新增目标<br>二级 |
| WMD-MAC13<br>macOS 更新编排 | 更新环共享目标/窗口/截止日期/暂停视图；macOS 使用实际支持的 DDM/原生命令及状态，呈现下载、用户延期、权限、重启和完成。 | 新增目标<br>二级 |
| WMD-MAC14<br>退役、重注册与生态迁移 | 按管理所有权移除 profile、应用分配、Agent 及凭据；保留审计并处理残留任务。跨 MDM 迁移只承诺已验证路径，必要时明确重新注册。 | 新增目标<br>二级 |
| WMD-MAC15<br>可选 Apple 企业增强 | 保留 Platform SSO、证书自动化、用户级管理深化和自助安装作为独立三级包；与管理控制台 OIDC、全平台 MSP 隔离分开立项。 | 新增目标<br>三级 |

## 关键规则与边界

默认建议采用 Rust 产品控制面 + NanoMDM 薄通道适配器，复用成熟协议处理；不把 Jamf/Fleet 整个平台嵌为第二控制面。NanoMDM 本身不提供完整注册、SCEP、ADE API 或 VPP 产品；其 DDM 转发接口也不等于声明、激活与状态仓库。缺失的业务由产品组合承担。[E05](../reference/external-sources.md#e05)[E06](../reference/external-sources.md#e06)

“基于 Rust 重写”在此约束自有业务控制面与自研 Agent 的演进，不自动要求外部依赖全部 Rust 化。若后续确定全链路纯 Rust，须独立评估 Apple 协议替代方案；本文不承诺已经存在等价可替换实现。默认复用选择为设计建议，不是已经部署的事实。

首批正式支持企业自有 Mac 的设备管理；BYOD/复杂多用户与全 Apple 移动平台未纳入首批。不能同时让两个原生 MDM 产品争夺同一配置 owner；与既有 Jamf/Fleet 共存先限定为 Agent-only 或经批准的管理迁移，不能把双 Agent 共存说成双原生 MDM 可写。

Apple MDM 的生产可用性依赖 APNs、证书和组织服务接入。私有部署不等于彻底断公网仍可保证 Apple 原生管理时效；完全隔离网络只对明确验证的 Agent/内部软件源能力作承诺。[E17](../reference/external-sources.md#e17)[E18](../reference/external-sources.md#e18)

## 验收场景

AC-06-18-01　MDM-only、Agent-only、双通道 Mac 分别验收；能看出哪项能力来自何通道，缺少另一通道不影响独立接入。

AC-06-18-02　完成原生 profile 与 DDM 两条不同交付路径；声明集合更新、设备状态晚到、用户通道缺失分别可诊断。

AC-06-18-03　演练 FileVault PRK、APNs 更新、Bootstrap Token 缺失、危险动作阻断与退役；不得以 API 成功代替终端证据。

---

# 06.19　WMD-REP：软件仓库控制面与 WinGet 私有源

目标是企业软件发布与消费闭环，而不是再做一个通用制品仓库。WinGet 私有源属于二级交付。

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-REP01<br>私有软件源对象 | 统一管理源 ID、类型、地址、owner、环境、凭据引用、信任策略、健康和启停；至少支持 WinGet REST Source 与 Homebrew Tap/产物源，软件源不是交付通道。 | 新增目标<br>一级 |
| WMD-REP02<br>接入与托管发布 | 支持接入现有私有源，并提供产品内受控包发布工作流：WinGet 生成/提交兼容 manifest/feed；Brew 发布至专用私有 Tap 和产物存储。不自研通用 Git 服务或二进制仓库。 | 新增目标<br>二级 |
| WMD-REP03<br>精确软件身份 | 软件实现绑定 source_id + package_id + version + architecture + installer/variant；Brew 使用完整 Tap 与 Formula/Cask 标识。禁止因同名公共包或模糊匹配改变来源。 | 新增目标<br>一级 |
| WMD-REP04<br>包提交与供应链校验 | 提交 manifest、安装物、哈希/签名、OS/架构、安装/检测/卸载定义与来源授权信息；元数据验证和实际安装验证分开，外部 URL 抓取受域名/大小/协议限制。 | 新增目标<br>二级 |
| WMD-REP05<br>审批、快照与分环发布 | 候选→验证→批准→发布→弃用/隔离；审批锁定源快照、manifest 摘要和产物摘要。Test/Pilot/Production 只提升已验证版本，不可原地覆盖同版本字节。 | 新增目标<br>二级 |
| WMD-REP06<br>WinGet 执行器 | 通过 Agent 执行明确源和精确包的查询、安装、升级、卸载、版本固定及状态查询；记录客户端版本、installer、用户/机器 scope、退出码和独立检测证据。 | 新增目标<br>二级 |
| WMD-REP07<br>无人值守与源认证 | 将源元数据认证、安装物下载认证、执行身份分开；按实际 WinGet 客户端和 REST Source 能力匹配。禁止默认共享管理员 token 或假定任意 OAuth 可无交互完成。 | 新增目标<br>一级 |
| WMD-REP08<br>源分配与公共源控制 | 按 Scope 配置允许的源/包、是否允许公共回退、可修改权限与漂移处理；默认托管任务必须使用明确来源。删除源前显示受影响应用和未完成执行。 | 新增目标<br>二级 |
| WMD-REP09<br>回退、下架与缓存撤销 | 发布引用可回退到保留快照；终端降级/卸载必须有专用方案。包隔离后阻断新授权和新下载，并处理缓存/短期凭据窗口，不能宣称瞬时撤销所有离线副本。 | 新增目标<br>二级 |
| WMD-REP10<br>运行与审计 | 记录源配置、发布者/审批者、安装对象、摘要、凭据版本及错误阶段；监测同步/下载/安装延迟与积压，源备份和软件产物保留纳入恢复方案。 | 新增目标<br>二级 |

## 关键规则与边界

私有仓库管理包含两个平面：控制面负责目录、审批、Scope、发布、回收与审计；数据面复用 WinGet REST Source、Git Tap、对象存储/现有制品服务。只运行 winget source add 或 brew tap 不构成完成。

微软提供 REST Source 参考实现，但示例依赖 Azure/CosmosDB；本地部署不能被隐式绑定 Azure。首批应选择已验证、可本地部署的兼容服务，或者实现有原生客户端互操作测试的最小 REST Source 适配，不另造软件包协议。服务的具体选型在技术设计中冻结，不改变本 PRD 的私有化与兼容目标。[E21](../reference/external-sources.md#e21)

安装上下文不等于执行进程身份。--scope machine 不能证明 WinGet 可在任意 LocalSystem 会话中使用；必须按获准客户端版本、包类型和安装策略实测。Source API 的认证成功也不能推导安装物 URL 可匿名或使用相同 token 下载。[E19](../reference/external-sources.md#e19)

首版最低闭环：一条完全受控 WinGet 私有源、一条私有 Brew Tap、内部可用产物地址、版本审批与目标分配、真实终端安装/核实/卸载、凭据撤销及审计。公共源同步、复杂外部仓库连接器可以逐步增加；两类私有源不能降为仅远期候选。

## 验收场景

AC-06-19-01　提交内部应用 → 校验与审批 → 发布私有源 → 组分配 → Windows 无人值守安装 → 资产核实 → 升级/卸载。

AC-06-19-02　同名依赖污染、包被替换、下载凭据失效、源下线、客户端不支持、安装状态不明分别验证。

AC-06-19-03　禁止公共回退的设备无法借错误源解析安装公共同名包；只读仓库角色无法发布或取出源密钥。

---

# 06.20　WMD-BRW：Homebrew 私有仓库与执行器

目标：在 macOS 上复用 Homebrew 的 Formula/Cask/Bottle 生态，以 Agent 统一执行和回执；不是开发替代 Homebrew 的包管理器。

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-BRW01<br>私有 Tap 与定义管理 | 支持 Git URL、受控分支/提交、Formula/Cask 清单与只读同步；托管编辑通过专用发布流程提交，禁止直接污染外部共享 Tap。 | 新增目标<br>二级 |
| WMD-BRW02<br>元数据与产物分别托管 | 分开管理 Tap 元数据、Bottle、Cask 下载物及所需依赖；地址、认证、摘要、保留和镜像策略分别配置。私有 Git 访问成功不代表产物可以获取。 | 新增目标<br>二级 |
| WMD-BRW03<br>架构、前缀与实例 | 发现 Apple Silicon/Intel、实际 brew 路径、版本、prefix、owner 与已有安装实例；默认使用受支持原生实例，不根据单个固定路径判断安装。 | 新增目标<br>一级 |
| WMD-BRW04<br>非 root 执行身份 | Agent 可拥有系统服务权限，实际 Brew 包操作必须切到已批准的非 root 用户；检测受支持的 as-console-user 或等价受控执行机制。无适用用户时等待，不创建隐式高权账户。 | 新增目标<br>一级 |
| WMD-BRW05<br>Bottle 与依赖闭包 | 校验 Bottle 对应 OS/架构/前缀、完整性与依赖可达性；生产默认优先批准二进制。缺 Bottle 不静默转源码构建或下载未批准工具链。 | 新增目标<br>二级 |
| WMD-BRW06<br>安装、升级与固定 | 管理 Formula/Cask 安装、升级、卸载和受支持 pin；结合 Tap 快照与产物保留约束版本。Homebrew 6.0 已有 Cask pin，旧客户端必须能力检测。 | 新增目标<br>二级 |
| WMD-BRW07<br>Tap 代码信任与审核 | Formula/Cask 代码及钩子须审批；按客户端版本管理显式 Tap trust，并绑定批准的远端与快照。预览不在带密钥的生产控制面执行任意 Ruby；来源变更须重新审核。 | 新增目标<br>一级 |
| WMD-BRW08<br>私有源凭据 | Git 与产物下载凭据分域、最小权限和有界有效期；不把长期 token 嵌入 Tap、URL、shell 参数或可读日志，执行后清理临时配置。 | 新增目标<br>一级 |
| WMD-BRW09<br>安装所有权与卸载保护 | 区分组织托管、用户已有、依赖引入和其他工具安装；默认不接管已有应用，不全局 autoremove，不把 cask zap 作为普通卸载默认行为。 | 新增目标<br>二级 |
| WMD-BRW10<br>隔离网络与版本恢复 | 内部镜像覆盖 Tap、批准的 Bottle/Cask 及依赖；允许网络目的地受控。回退要求历史元数据和产物均保留，并区分配置回退与不可保证的数据降级。 | 新增目标<br>二级 |

## 关键规则与边界

Brew 的“私有仓库”不能只替换一个下载 URL。管理对象包括 Git Tap、Formula/Cask 定义、Bottle/Cask 产物、依赖、执行用户、Homebrew 实例与可复现发布快照。[E22](../reference/external-sources.md#e22)、[E23](../reference/external-sources.md#e23)、[E24](../reference/external-sources.md#e24)、[E25](../reference/external-sources.md#e25)、[E26](../reference/external-sources.md#e26)、[E27](../reference/external-sources.md#e27)、[E28](../reference/external-sources.md#e28)

Homebrew 6.0.0 在 2026-06-11 的官方发布说明已加入该能力。但 pin 不冻结所有依赖、元数据、安装钩子和第三方 App 自更新，产品仍需快照、产物保留和应用级更新控制。[E27](../reference/external-sources.md#e27)

as-console-user 是当前官方手册中的能力，不保证旧端存在；受控用户切换由版本探测选择。默认不支持多个用户任意共享一个可写前缀，不强制 chown 整个目录，不绕过 Gatekeeper、TCC 或 SIP。复杂多用户前缀管理作为后续明确支持项。[E25](../reference/external-sources.md#e25)[E26](../reference/external-sources.md#e26)

## 验收场景

AC-06-20-01　同一私有 Tap 提供一个 Formula 与一个 Cask，验证支持矩阵内各架构的安装、升级、固定、卸载与清单回收；矩阵外组合在预检阻断。

AC-06-20-02　用 root Agent、无登录用户、已有其他用户前缀、缺 Bottle、被撤销凭据、公共网阻断验证失败边界。

AC-06-20-03　用户自装同名 App、共享依赖及自更新 App 不被无提示接管；普通卸载不删除用户数据。

---

# 06.21　WMD-COL：统一数据采集与可扩展字段

目标：同一采集请求、数据字典、资产读模型和查询语义，支持 Agent（osquery/脚本）与 MDM 的差异来源。

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-COL01<br>统一采集入口与来源 | 采集通道仅 Agent/MDM。Agent 内含内置采集、osquery、自定义脚本；MDM 内含 Windows CSP 与 Apple 原生响应/DDM 状态。Manual/API 为资产赋值来源，不伪装成终端观测。 | 新增目标<br>一级 |
| WMD-COL02<br>跨平台采集模板 | 模板以字段目标和适用范围定义，按平台/通道绑定 SQL、脚本或 MDM 读取映射；可发布版本、试运行和灰度，不要求管理员逐设备填写平台判断。 | 新增目标<br>一级 |
| WMD-COL03<br>周期、增量与资源预算 | 计划支持周期、抖动、触发条件、超时、行数/字节限制和最大并发；批次记录 full/delta、游标或快照完整性，失败支持有界补偿。 | 新增目标<br>二级 |
| WMD-COL04<br>即时与离线采集 | 即时查询为异步任务，支持选择仅在线或等待下次签入、截止时间与逐设备状态。返回已收到部分结果并保留覆盖率，不承诺离线设备实时响应。 | 新增目标<br>一级 |
| WMD-COL05<br>osquery 集成 | 复用 osquery 查询/计划能力，Agent 统一监督其生命周期和任务归属；校验表/列/版本、控制高风险表和输出，区分查询错误、零行、权限受限与未执行。 | 新增目标<br>一级 |
| WMD-COL06<br>扩展字段注册与类型 | 复用 WMD-X 的唯一字典，支持 string/integer/number/boolean/timestamp 及受限数组/对象路径；声明命名空间、schema 版本、单位、枚举、长度、敏感级别和可搜索性。 | 新增目标<br>一级 |
| WMD-COL07<br>观测来源、时间与合并 | Observation 带设备/注册世代、字段版本、来源、采集/接收时间、批次/序列、有效期和证据状态；按字段权威与新鲜度选值，不采用简单最后到达覆盖。 | 新增目标<br>一级 |
| WMD-COL08<br>未知、删除与过期语义 | 区分未采集、不支持、无权限、失败、已过期、合法空值和明确删除；保留 last_known 与当前质量。只有声明完整的快照或 tombstone 才可删除旧清单项。 | 新增目标<br>一级 |
| WMD-COL09<br>字段消费与自动化 | 字段进入设备详情、查询、智能组、合规和受控模板变量；用相同类型/权限语义，引用缺失时拒绝发布。防止采集→分组→修复→采集的无限循环。 | 新增目标<br>二级 |
| WMD-COL10<br>隐私、保留与原始结果 | 预置采集不包含个人文件、浏览/聊天内容等原排除数据；脚本/osquery 需审核允许范围、输出脱敏与留存。敏感凭据进入专用托管，不进扩展字段。 | 新增目标<br>一级 |
| WMD-COL11<br>可选自定义采集扩展 | 先支持字段映射与脚本，不为新增字段创建新 Agent 或新表引擎；只有确需新系统数据源时才接入签名、版本锁定的 osquery 扩展并控制权限/资源。 | 新增目标<br>三级 |

## 关键规则与边界

统一模型区分 FieldDefinition（字段语义）、CollectorBinding（如何得到）、Observation（来源证据）、ResolvedAsset（当前选值）。不要把所有值直接覆盖进一个无类型 JSON 后交给每个功能自行解释。

示例：device.disk_encryption.enabled 可以由 Windows 原生、Apple 原生或 Agent 观测提供；custom.asset_tag 是人工/API 资产赋值；custom.corporate_agent.version 可以绑定 Windows osquery/PowerShell 与 macOS osquery/shell。脚本输出优先使用版本化 JSON，Jamf 的 result 标签只作为显式兼容解析方式，不成为统一协议。[E03](../reference/external-sources.md#e03)

osquery 是采集执行器，不等于策略配置引擎。其 SQL 表跨平台程度不同；不能要求同一 SQL 文本适配所有 OS，也不能因为语句是 SELECT 就视为低风险或无隐私影响。Agent 应避免与另一产品同时修改同一 osquery 实例配置；共存时使用独立受控实例/端点或明确集成契约。[E29](../reference/external-sources.md#e29)、[E30](../reference/external-sources.md#e30)、[E31](../reference/external-sources.md#e31)

扩展字段不等于可信设备证明。主机管理员可影响本地脚本或查询结果；用于高风险准入时必须另定义设备身份、证据真实性、时效和失效策略，不能自动升级为零信任认证。[范围规则](../rules/project-scope.md)

## 验收场景

AC-06-21-01　新增 custom.corporate_agent.version，用 Windows osquery 与 macOS shell 试运行；另选原生 MDM 明确支持的资产字段做映射，三种来源均进入同一搜索与智能组。

AC-06-21-02　验证脚本失败、权限不足、空结果、过期、部分快照、断网旧结果晚到和来源冲突；查询、分组、合规不产生不同结论。

AC-06-21-03　大结果、慢查询、敏感字段、错误 schema、未批准自定义扩展都不能绕过预算与访问控制。

---

# 06.22　WMD-CH：策略通道选择、冲突与恢复

此模块拥有“如何安全选通道”的业务规则；虚拟执行层提供模型，通道适配器负责协议。没有新增平行策略引擎。

| 需求编号 / 名称 | 产品要求 | 历史基础 / 分级 |
| --- | --- | --- |
| WMD-CH01<br>双通道选择策略 | 每条策略选择 auto、agent_only 或 mdm_only，可限制允许通道与偏好。auto 先判能力与前提再选择；没有可行路径时显示 blocked/unsupported，不盲目广播两个通道。 | 新增目标<br>一级 |
| WMD-CH02<br>混合策略拆成显式步骤 | 一条业务策略可含 MDM profile、Agent 脚本和软件确保等多个步骤，各自唯一通道、依赖、前提与核实；与同一步骤双通道同时写入严格区分。 | 新增目标<br>二级 |
| WMD-CH03<br>资源写入所有权 | 按设备/用户对象、逻辑资源和 generation 确定单一写 owner；同一应用/配置被两个策略或工具管理时显示冲突、优先级与接管决定。 | 新增目标<br>一级 |
| WMD-CH04<br>切换与结果不明 | 只有旧写路径被证实未执行、取消成功或完成状态核实，且替代路径语义/权限一致时，才允许受控切换；超时本身不是自动 fallback 的授权。 | 新增目标<br>一级 |
| WMD-CH05<br>统一派发证据 | 区分推送接受、设备签入、原生受理/Agent 执行、应用效果与合规评估。DDM 属于 Apple MDM 子机制；APNs/WNS 属于通知机制，不新增业务通道。 | 新增目标<br>一级 |
| WMD-CH06<br>离线与用户上下文 | 任务等待支持 offline、user_absent、needs_user_approval、reboot_required 等原因和有界有效期；Apple 用户通道是 MDM 下的目标上下文，不是 Agent/MDM 的第三并列项。 | 新增目标<br>一级 |
| WMD-CH07<br>执行与核实可跨通道 | 写入通道唯一，核实可选另一只读通道辅助；证据不足时显示 applied_unverified 或 conflict，不能用第二通道重复写入代替验证。 | 新增目标<br>二级 |

## 关键规则与边界

通道维度只有 agent、mdm；执行器维度可以是 powershell、shell、osquery、winget、brew、windows-csp、apple-mdm、apple-ddm。字段来源也可细分为 agent.osquery、agent.script、mdm.windows、mdm.apple、manual、api，但不会产生六套产品设备身份。

通道选择建议默认：原生配置用 MDM；软件按应用定义选择原生安装或 Agent 包管理器；任意脚本仅走获准 Agent 执行器；标准资产优先满足采集模板的权威/时效策略。不得规定所有能力一律 MDM-first 或 Agent-first，也不得让“两个通道都在”意味着“两个通道都写”。

原生 MDM 不能共享自研 Agent 的本地互斥锁。服务端 generation/fencing 能防止自己的重复派发和旧结果覆盖，但不能证明终端永不晚执行旧原生命令；需配合到期、查询、人工处置或下一轮期望状态收敛。此限制必须保留在恢复设计与产品文案中。

## 验收场景

AC-06-22-01　同一逻辑策略面向 Windows/macOS 混合组，结果能逐步展开到一个写通道和选定只读核实通道。

AC-06-22-02　模拟 MDM 结果超时、旧命令晚执行、Agent 离线、用户不在线；验证不存在危险自动跨通道重试。

AC-06-22-03　两个策略管理同一软件、一项配置从 Profile 转 DDM、策略退出 Scope 时均有明确所有权与清理规则。

---

# 07　控制台需求与信息架构

统一 API 与统一控制台必须使用同一能力/字段/状态来源，不让 UI 再维护一份操作系统判断表。

| 界面域 | 必须呈现的信息与操作 |
| --- | --- |
| 设备中心 | Windows/Mac 混合列表；物理设备与 enrollment 关联；Agent/MDM 状态、管理授权、能力与缺少前提；标准/原生/自定义字段及时间/来源。 |
| 策略中心 | 逻辑意图、平台模板、Scope、通道模式、步骤依赖、资源 owner；发布预览按“可执行/阻塞/不支持”分组；无隐形双发。 |
| 执行中心 | 计划版本、设备/用户对象、通道、执行器、原生码、等待原因、结果证据、重试/取消权限；展开 MDM/DDM/Agent 各自步骤。 |
| 软件与仓库 | 逻辑应用及平台实现；WinGet 源、Brew Tap/产物源；提交/验证/审批/快照/发布/隔离；凭据只显示引用/到期，不显示明文。 |
| 采集与字段 | 内置/MDM/osquery/脚本模板；平台适用性、权限、试运行、调度预算；字段字典、引用、类型变更影响、观测与当前选值。 |
| Apple 管理 | APNs/身份 CA/SCEP/ADE/应用许可状态与到期；Profile/DDM；Bootstrap Token、FileVault、Recovery Lock 采用独立访问流程。 |
| 组/合规/更新 | 复用标准字段和条件编辑；混合 OS 组计数一致；未知/过期可筛选；更新状态保留平台特有前提。 |
| 审计/系统 | 管理主体、变更、审批与操作证据；源/证书/任务队列/投影延迟；SSO/RBAC、部署配置和备份恢复。 |

异步任务受理后立即显示 operation_id、目标数量与可预期等待阶段，不以长连接是否保持作为成功标准。高危动作展示对象、影响、通道及不可逆性，前后端均校验授权。批次只显示汇总不能替代逐设备失败诊断。

标准操作无需用户重复选择 OS；原生模板编辑明确提示平台专用；必要差异不隐藏。未知字段、无权限、无设备、尚未采集、过期、真正为空分别展示。控制台支持中文和英文；仍不提供 UI 导出或 CSV 导入导出。[D02](../reference/historical-sources.md#d02)[D15](../reference/historical-sources.md#d15)

---

# 08　核心对象与状态语义

*现有词汇保留；新增状态只能按契约演进引入*

| 对象 | 历史状态 / 目标方向 | 不可混淆的产品语义 |
| --- | --- | --- |
| MDM 命令 | 历史：queued → sent → success/failed；可重试 failed → queued。[C25](../reference/historical-sources.md#c25) | sent 是已下发，不是设备已应用。 |
| 策略 | 历史：draft → active ↔ paused；active/paused → archived。[C26](../reference/historical-sources.md#c26) | 暂停策略不等于撤销所有已应用效果。 |
| 策略执行 | 历史：pending → running → success/failed/aborted；失败可按规则重试。[C26](../reference/historical-sources.md#c26) | aborted 表示执行流程中止，不代表设备状态自动回滚。 |
| Agent 任务 | 历史：pending → dispatched → completed/failed。[C27](../reference/historical-sources.md#c27)；D08 增 executing。 | 新增 executing 须协议升级；历史客户端尚不产生真实执行终态。 |
| 统一设备 | 各通道在线状态 + lifecycleState；模型含 retired/pending_reenroll 等。[C14](../reference/historical-sources.md#c14) | 在线、注册有效、证书可用、合规是独立维度。 |
| 应用安装 | 规划：not_installed → downloading → installing → installed/failed。[D05](../reference/historical-sources.md#d05) | installed 必须有检测或原生可靠结果；退出码不当然等于目标状态。 |
| 合规 | 历史有 compliant/non_compliant/pending/unknown；规划包含宽限期。[C31](../reference/historical-sources.md#c31)[D05](../reference/historical-sources.md#d05)[D07](../reference/historical-sources.md#d07) | 过期证据与缺失证据不可当作通过。 |
| 预注册 | 规划：pending → matched/expired。[D05](../reference/historical-sources.md#d05) | 已匹配资产资料不代表已经持有有效管理证书。 |

## 最小可追溯数据要求

建议在相关管理证据中保留：产品设备标识、通道设备标识、策略/应用/脚本及版本、执行/任务/命令标识、关联事件或请求标识、发生与接收时间、当前阶段、结果码、原因与可重试性。该清单是产品追踪要求，不规定数据库列名。

资产值附带来源、类型与新鲜度；Scope 解析结果附带引用组与版本/时间；敏感材料只保留受控标识，避免进入普通日志、搜索与 Webhook。

> 实施时须检查现有 API 响应、写模型和读模型三处语义，不仅修改状态枚举。尤其重新激活与证书恢复的响应不得自相矛盾。[C14](../reference/historical-sources.md#c14)[C22](../reference/historical-sources.md#c22)[C23](../reference/historical-sources.md#c23)

## 目标对象与统一状态

| 对象 | 关键职责 |
| --- | --- |
| Device / Enrollment / CapabilitySnapshot | 统一业务设备、独立通道注册/认证、可执行能力及计算依据。Apple 用户通道保留用户主体。 |
| Operation / Plan / Step / Execution | 请求意图、不可变目标计划、各步骤的唯一写通道、真实尝试与 generation；期望状态与历史分开。 |
| Application / PlatformVariant / Source / Release | 逻辑软件与平台版本；元数据源/产物源及不可变批准快照；禁止 packageId 单独作为跨源唯一身份。 |
| FieldDefinition / CollectorBinding / Observation | 字段语义、如何采集、逐来源证据；形成 ResolvedAsset 后供查询/分组/合规统一消费。 |
| AppleDeclaration / NativeConfiguration | Apple 声明与传统 profile 各自的 ID、版本、状态与删除语义；不将声明集合强行塞入单条同步命令。 |
| SecretRecord / CredentialReference | PRK、Bootstrap Token、Recovery Lock、仓库和 APNs 等材料分域存储及授权；不进入普通字段字典。 |

执行目标状态：accepted → planned → queued/waiting_device → executing/processing → awaiting_verification → verified 或 failed；中间可有 waiting_user、waiting_reboot、blocked；结果丢失为 outcome_unknown；已被新版本取代为 superseded。具体枚举在 schema 设计时冻结，但这些可观察差异不能被合并丢失。

源快照状态：draft → validating → approved → published → deprecated/quarantined；published 引用不可原地换字节。状态回退不代表端上应用数据可降级。

观测质量使用独立维度，不能同时混在“值”与“设备在线状态”中：known、unknown、unsupported、permission_denied、collection_failed、stale、not_collected，加合法 null 与明确 tombstone。source_authenticity/assurance 与 freshness 也分开：新鲜的脚本值并不自动可信。

### 标准字段示例

| 字段 | 共同语义 | 平台/来源差异 |
| --- | --- | --- |
| device.os.name / version | 实际 OS 与版本，不由注册模板填充为事实 | 原生查询或 Agent；保留 build 字段。 |
| device.disk_encryption.enabled | 管理范围内约定系统卷的加密状态 | Windows BitLocker 与 Mac FileVault 适配；多盘状态另建清单。 |
| software.installations | 受观察安装实例及版本/来源/owner | WinGet/Brew/原生列表可能覆盖不同集合，禁止简单覆盖合并。 |
| custom.corporate_agent.version | 企业定义应用版本，类型固定 | 同一字段可由平台 SQL/脚本实现；带来源与质量。 |
| custom.asset_tag | 组织资产标签 | Manual/API 赋值，不伪装成 MDM 设备自报事实。 |

共享 schema 必须同时规定标识、单位、枚举、时区、空值、兼容规则与结果强度，不能只生成同名 DTO 就视为统一抽象完成。

---

# 09　非功能要求与目标口径

容量与性能数字须在发布前按场景冻结并通过测试；历史文档中的相互冲突指标见 [历史性能目标](../reference/winmdm-baseline.md)，不作为本仓已支持规模。

| 主题 | 发布前必须明确并验证的要求 |
| --- | --- |
| 设备规模 | 硬件配置、设备总数、在线比例、管理场景与采样窗口。 |
| 注册并发 | 注册速率、测量窗口、成功判据及证书和数据库配置；测量到注册完成。 |
| 策略时延 | 分别定义有推送、无推送与离线场景的预算，保证轮询配置与承诺相容。 |
| 组评估 | 固定规则复杂度、设备数和并发变化，测量成员落地及后续 Scope 传播。 |
| Agent 开销 | 分别测试静默、采集、脚本、安装和离线恢复的 CPU 与内存，覆盖 Windows/macOS。 |
| 可用性与恢复 | 冻结 HA、RPO/RTO、备份范围和恢复验证；纳入关键凭据、任务和审计。 |
| 安全与隐私 | TLS、RBAC、敏感数据保护；禁止采集个人文件、聊天、浏览历史、精确 GPS；远程协助需用户同意。 |
| 兼容与升级 | 发布 OS/架构/注册类型/通道能力矩阵，明确 API、Agent、服务端与前端兼容窗口。 |

## 不可用数量取代的质量要求

无静默丢失已承诺的关键任务/审计；重复或过时消息不能误改终态；鉴权失败不产生副作用；升级失败可恢复；状态未知不能显示已完成。验收依赖真实场景证据，不设“必须有若干 Provider/测试”的数量门。

注册率、同步率、合规率等业务观察指标须明确分母、采样范围和客户目标后，才可作为发布承诺。

## 新能力的非功能门槛

预算须分为 Agent 本体、osquery 子进程、脚本与软件安装四类；各类预算分别测量，总进程树开销也需满足发布约束。为每个采集模板配置执行超时、并发、结果字节/行数、频率与留存；大型全量清单必须分页/分块并记录完整性。

脚本、采集 SQL、Tap 代码、包发布和高危 MDM 命令须分级授权、可审计，生产审批与执行主体隔离。持久任务/审计失败应拒绝或明确降级，不静默接受；签名仅证明来源和完整性，不能证明脚本安全。

时效 SLO 分为服务端排队、通知、设备在线响应、用户批准、安装执行、状态核实和投影刷新；受 Apple 服务、终端离线或用户交互影响的阶段不混成一个保证“几秒完成”的指标。所有统计分母分开显示 eligible、unsupported、blocked、waiting 与 confirmed。[E17](../reference/external-sources.md#e17)

Mac Agent 安装/升级要验证签名、公证、权限与服务恢复；软件源验证断点续传、摘要、凭据轮换和备份。服务器、Agent、osquery、Brew/WinGet 与 schema 的兼容窗口在发布前冻结并保留跨版本证据；支持上限以压测结果为准。

---

# 10　产品验收与发布门槛

产品验收覆盖以下 Windows 与跨平台场景。每个 T3 在直接产品仓独立 issue/PR，需写明必要性、输入/输出、真实设备矩阵和故障范围；一行不等于一个大而全 PR。[验证规则](../rules/verification-scope.md)

| 场景 | 必须证明的结果 | 关键需求 |
| --- | --- | --- |
| T3-01 初始化与双通道接入 | Setup 安全关闭；MDM-only、Agent-only、双通道分别正确注册/展示，非法接入被拒绝。 | E01–E04、D01、A01–A03 |
| T3-02 智能组驱动配置 | 设备属性 → 组 DIFF → Scope → 新执行 → 真实 CSP 结果；排除对象不接收配置。 | G01–G04、P01–P04、C01–C04 |
| T3-03 Agent 执行与补传 | 真实 Agent 执行签名脚本，超时、安全拒绝、断网补传与重复回执行为正确。 | R01–R05 |
| T3-04 EA 参与管理 | Manual/MDM 子集或 Script 来源分别产生属性，再驱动搜索和分组；失败/过期明确。 | X01–X05、Q03、G05 |
| T3-05 应用生命周期 | 选定通道安装、检测、升级、卸载、失败暂停、断点续传及权限校验。 | S01–S06 |
| T3-06 凭证托管 | 密钥轮换、安全托管、授权查阅与审计；拒绝越权且日志无明文。 | K01–K04 |
| T3-07 更新环 | 更新分环、暂停恢复与实际设备状态一致；失败与未知可区分。 | U01–U03 |
| T3-08 退役与权限失效 | 退役处理证书/任务；无效账户/会话失权；重新激活不会掩盖待重注册。 | D03–D05、E04、A01–A04 |
| T3-09 故障与版本升级 | 数据库/消息/磁盘/进程故障及升级失败后，状态、任务、审计可恢复且可解释。 | P04、M01–M05、O01–O04 |
| T3-10 macOS 三种接入组合 | MDM-only、Agent-only、双通道各自可用；注册关联、非法证书、退役与重注册正确。 | MAC01/02/11/14、V01/V08 |
| T3-11 跨 OS 统一接口 | 同一采集和配置/软件意图面向混合组，不要求调用端按 OS 改业务结构；不支持目标明确列出。 | V01–06、CH01/02 |
| T3-12 Profile/DDM 状态收敛 | 真实 profile 与 DDM 的安装/更新/移除、重复/乱序状态、所有权冲突和用户通道分别成立。 | MAC04/05、V09、CH03/05 |
| T3-13 WinGet 私有源闭环 | 内部包审批发布、精确源安装、升级/卸载、无人值守、摘要错误、凭据撤销和公共同名包防混淆。 | REP01–10、S06 |
| T3-14 Brew 私有源闭环 | 私有 Tap 与私有产物、Formula/Cask、非 root 身份、架构/前缀、pin、缺依赖、无人登录和安全卸载。 | BRW01–10 |
| T3-15 三类采集与扩展字段 | Agent/osquery、Agent/script、MDM 分别产出字段，进入同一搜索/组/策略；类型、时间和来源可追溯。 | COL01–09、X01–05 |
| T3-16 不可靠结果与冲突 | 断网旧结果晚到、部分快照、失败/空值、时钟偏差、MDM/Agent 矛盾不会造成误覆盖、误删或自动高危修复。 | COL07/08、V07/09、CH04/07 |
| T3-17 跨通道重复副作用 | MDM 超时但晚执行时不自动 Agent 双发；取消未必成功、软件 owner 冲突与配置迁移可解释。 | CH01–07 |
| T3-18 Apple 安全与更新 | FileVault 托管/轮换、Bootstrap Token 前提、恢复访问权限、更新的用户批准/重启与危险动作。 | MAC07–09/12/13 |
| T3-19 Apple 外部依赖 | APNs/ADE token 到期/不可达、CSR 签名来源、续期和服务恢复；私网可部署不伪称全隔离可运行。 | MAC01/03、O02–04 |
| T3-20 升级与迁移 | 旧 Windows 行为、共享 schema、旧 Agent、源快照、敏感材料与观察记录在版本升级/回退后仍正确。 | V12、REP09/10、O03 |

## 产品验收的必要性与边界

T3-10/11 证明本产品最核心的“统一管理两 OS”；T3-13/14 证明私有仓库不是 URL 配置页面；T3-15/16 证明自定义字段可被安全消费；T3-17 防止双通道重复副作用；T3-18/19 证明 Apple 专属能力和外部依赖的真实约束；T3-20 防止重写破坏既有用户。

证据至少包括服务器/Agent/依赖版本、OS/芯片、注册方式、前提、具体请求、计划、原始与规范化回执、终端核实、故障点、恢复结果和脱敏审计。模拟设备只能验证部分协议行为，不能替代真实 Mac/Windows、包管理器身份和用户授权验收。

R0/R1 不提前强制建设所有 R3 T3；但发布范围内任何危险动作、脚本、密钥和源凭据必须同时验证权限与泄漏边界。外部组件自身测试不能替代产品 T3。

## 阻断发布的结果

跨 OS 错误路由、未授权执行、源/产物被替换仍通过、恢复密钥或长期凭据泄漏、APNs 接受就显示设备完成、超时自动双发不可逆动作、unknown 被算合规、部分采集清空全量资产、旧回执覆盖新 generation、Agent 只记日志却显示已执行，均阻断相应产品包发布。

---

# 11　远期能力与明确排除项

| 能力族 | v0.2 处理 |
| --- | --- |
| macOS、WinGet/Brew、osquery、扩展字段 | 已进入本产品正式目标，不再放在远期候选清单；按第 05 节分阶段完成。 |
| 自助与软件许可深化 | 保留自助安装、审批、应用许可分析等三级增强；Apple 原生许可分配自身属于 MAC10 必要部分。 |
| Apple 企业增强 | Platform SSO、复杂 BYOD/多用户、更多 Apple 平台分别立项；管理台 OIDC 不自动产生 Mac 登录 SSO。 |
| 遥测与高级支持 | 远程桌面、屏幕/文件协助、深度时序分析、通知、P2P、多地域按独立产品包，遵守原隐私边界。 |
| 仓库与采集平台化 | 更多源连接器、完整源码构建农场、公共仓镜像平台、osquery 自定义扩展市场不是首版前提。 |
| 范围排除 | 不恢复 CSV/UI 导出、GPO 迁移、公有 SaaS、EDR 替代、Windows 7 或自动加入 Linux/iOS/Android。 |
| RSS 不扩张 | 设备政策、Apple/Windows 协议、软件源控制面、采集字段管理、部署和 T3 不因“通用”二字自动接纳到 RSS。 |

---

# 12　基于 RSS 重写时的产品约束

*此页限定责任与不退化目标，不展开 crate 或 PR 设计*

基于 RSS、使用 Rust 重写时，目标应是迁移与补齐上述产品行为，而不是照搬 Go 微服务数量、所有 Provider 类型或历史 schema。现有 Go 实现作为业务语义和回归场景来源，不直接充当 Rust 完成证据。

| 责任 | 应由谁拥有 | 不得混入 |
| --- | --- | --- |
| 注册/设备/策略/合规/软件/身份产品语义 | MDM 直接产品仓 | 不能因实现用到通用机制就归 RSS 管理。 |
| 协议与设备认证 | MDM 产品仓及其明确采用的外部系统 | Windows CSP/WSTEP/SyncML、Apple MDM/DDM/APNs/ADE、设备准入不是 RSS 的产品职责。 |
| 公共契约、事务消息、Saga、投影、收敛、已接纳设备命令基础库 | RSS 主仓；按已接纳公共边界消费 | 不得把范围接纳视为 crate 已发布或生产已完成。 |
| 业务读模型、策略判断、应用装配、配置、业务表/迁移执行 | MDM 产品仓 | 不把产品 assembly 或服务端部署转回通用库。 |
| 产品 T3、交付运维、升级/恢复 | MDM 直接产品仓 | 不再设孵化仓；T3 必须独立限定 issue/PR。 |

## 重写不退化要求（建议）

先冻结现行外部接口的已承诺行为和支持矩阵，再决定版本兼容窗口。迁移应保留有效设备身份/证书关系、设备关联、策略版本与 Scope、资源引用、关键历史和审计关联；无法无损迁移的项目必须提供明确的重新注册或补偿流程。

不得以新语言重写为由把已有搜索、组重算、SSO 映射、WNS 重载、审计可靠性增强重新降为“待从零研发”；也不得因 RSS 存在 outbox/saga 等组件就标记应用安装、脚本或 EA 已完成。

自有服务端与 Windows Agent 最终均采用 Rust；服务端位于 rss-mdm，Agent 位于 rss-mdm-agent，macOS 自有 Agent 沿 Rust 平台适配路线建设。现有前端先保留。分仓契约与迁移路线见 [项目目标](project-goals.md)；具体切换节奏、前端版本和兼容期限在对应交付冻结。

具体工程路线写入 [架构文档](../architecture/README.md)，遵循本仓范围与验证规则。

## 产品能力归属

统一执行层中的业务意图、能力规则、通道选择与资源 owner 归 MDM；可独立复用的持久执行/消息恢复仅通过 RSS 已接纳 API 消费。字段字典、采集模板、WinGet/Brew 源与应用模型、macOS 认证/协议和产品 Agent 均归产品。

产品需求不直接要求新增 RSS 通用平台或插件系统。后续确有第二独立消费者、唯一职责和可独立发布边界时再单独做 RSS 准入评审。NanoMDM、osquery 和包管理器以受控外部依赖形式组合，不把其内部数据库当跨域公共接口。[范围规则](../rules/project-scope.md)

---

# 13　已更新决策、未决参数与风险

## 已明确的产品范围

| 决策 | v0.2 结论 |
| --- | --- |
| DEC-01 文档关系 | 本文件为 rss-mdm 产品需求入口，状态为评审草案；历史 PRD 仅作参考，不与本文件共同维护产品范围。 |
| DEC-02 需求编号 | WMD-* 作为稳定需求编号，不与实现任务或历史 Sprint 编号混用。 |
| DEC-03/04 原排除项 | CSV/UI 导出/GPO 迁移继续不纳入；macOS ADE 不以 CSV 预注册为依赖。 |
| DEC-06 通道归属 | 软件按包、平台、前提选择 Agent/MDM；WinGet/Brew 不作为第三通道；MDM 安装 MSI 的能力由矩阵验证。 |
| DEC-08 字段来源 | Agent 内置/osquery/脚本、MDM 为设备采集；Manual/API 为赋值；LDAP 不自动纳入。 |
| DEC-13 macOS 地位 | 从远期提升为正式目标，新增实际协议/Agent/安全/软件/更新需求；平台枚举不计完成。 |
| DEC-14 统一接口边界 | 业务契约跨 OS 共用，适配器/平台模板保留差异，Native MDM 不改成自研 Agent 协议。 |
| DEC-15 软件源优先级 | WinGet 与 Brew 私有源为正式二级包，不是无限延期候选。 |
| DEC-16 复用方向 | 默认推荐 NanoMDM 协议组件、osquery、WinGet/Brew；不上线第二个 Jamf/Fleet 全量控制面。属于技术方向建议。 |

## 仍需在对应版本冻结的参数

| 参数 / 风险 | 默认处理与阻断条件 |
| --- | --- |
| Apple 资质和组织接入 | 确定 Vendor CSR 签名来源、APNs/ADE/应用许可责任人及续期机制；缺少可持续来源阻断 Apple 生产发布，不阻断不依赖它的 Agent 研发。 |
| OS/芯片/用户支持矩阵 | 冻结真实机型、稳定 OS、Agent/osquery/WinGet/Brew 版本、设备/用户目标；未测组合不宣称支持。 |
| WinGet 源部署与认证 | 冻结本地兼容源实现、无交互认证和安装物授权；不得把 Azure/交互登录偷偷设为必需。 |
| Brew 用户与前缀 | 缺合适非 root 用户默认等待；多用户/非标准前缀是否支持必须显式记录，不用危险改权限解决。 |
| 现有软件接管 | 默认只管理产品创建的安装；接管既有软件和共享依赖需批准；明确 cask 数据清理边界。 |
| 性能、预算、数据保留 | 容量、时延和 RPO/RTO 须按场景冻结；新增 osquery 与软件下载负载需单独压测。 |
| 敏感材料方案 | 统一加密与访问设施，但 PRK/Token/Recovery Lock/LAPS 各有验证方法；秘密不得放普通字段。 |
| 身份与多租户 | 管理台本地/OIDC 继承；Mac Platform SSO、MSP 隔离另议，不能因多 IdP 或多 APNs topic 自动宣称多租户产品。 |
| 兼容窗口与切换节奏 | 两端自有实现采用 Rust；冻结 Windows Agent 切换批次、Mac Agent 支持矩阵、实际前端 revision 与旧 API 期限，禁止同设备双控制 owner 长期并存。 |
| 版本强制包与人力 | 无客户规模/预算/资源信息，不编造交付日期；依赖不受冲突影响的 R0/R1 可先推进。 |

“待冻结参数”不改变已列明的核心能力范围；它们决定实现 profile、支持矩阵和验收条件，而不是否定目标。

---

# 14　评审与来源导航

RSS MDM 的产品目标是：基于统一业务契约和可恢复执行，组合 Agent 与原生 MDM 管理 Windows/macOS，并通过统一资产字段、组、策略及私有软件仓库实现企业终端运维闭环。

本产品先冻结身份、字段与持久化消费边界，以 Windows MDM 只读纵切证明真实接入，再推进原生策略与 Rust Agent；Mac 注册/Agent、三类采集按依赖并行，WinGet/Brew 源元数据与发布后端可提前独立建设，终端执行和真实安装验收仍消费可信 Agent 与已交付后端，Apple 企业能力按自身依赖推进。不能先分别做两套 OS 控制面，最后仅在 UI 合并列表；也不能为统一而抹去 Apple 权限、WinGet 用户上下文或 Brew 前缀/用户模型的差异。

产品负责人确认功能包与默认行为，安全负责人确认执行/源代码/凭据权限，运维负责人确认 Apple 外部依赖与支持矩阵，研发负责人确认适配器/兼容边界，前端负责人确认状态与证据展示。未经这些闭环，本文中的目标不得转换为产品已支持声明。

外部对标只采用厂商/项目官方资料。主要参考用途是产品对象、协议边界和可验证限制，不借用对方产品的性能或认证结论；尤其 Fleet 软件部署指南标记 Premium，不推导“开源即所有功能免费”。[E07](../reference/external-sources.md#e07)

需求表、各模块 AC 场景与第 10 节 T3 表共同定义需求和验收映射。来源索引见 [参考资料](../reference/README.md)。
