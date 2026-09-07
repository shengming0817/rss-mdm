# 项目目标

本文件拥有工程目标与交付方向；功能需求、排除项与需求编号仍由 [PRD](rss-mdm-prd.md) 拥有。当前为目标与设计基线，尚未实现产品代码。

## 已确定的方向

1. 自有服务端以 Rust 重写，直接消费 RSS 已接纳的公共组件。首期不新增 RSS 通用 crate，不使用孵化仓，不建立第三个 mdm-common 中间仓。
2. `rss-mdm` 拥有产品服务端、管理 API、MDM 网关、业务模型、协议契约、产品迁移与部署；`rss-mdm-agent` 拥有自有 Rust Agent、平台适配、安装与可信升级。两个独立 Cargo workspace 和发布生命周期，不以相邻目录 path 耦合。
3. Windows Agent 最终迁移到 Rust；macOS 自有 Agent 同样按 Rust 平台适配路线建设。现有前端先保留，通过明确 API/会话兼容接入；“保留前端”不表示已取得或验证其源码。
4. Windows 与 macOS、统一执行、Agent/MDM 两通道、osquery/脚本/MDM 采集、WinGet/Brew 私有源仍是 PRD 正式目标。Windows 优先验证路径不把 macOS 或软件源退回三级候选。
5. RSS 提供持久化机制；产品定义采集、资产、策略、身份与协议语义。Rust 要求约束自有实现，不要求将已选择的 NanoMDM、osquery、包管理器等第三方依赖重写为 Rust。
6. 迁移默认保留可验证的既有设备身份，按设备群单一控制 owner 逐步切换。不存在存量部署时不虚构迁移负担；存在时先盘点证书、管理 URL、数据与旧任务。

## 什么算成功

- 第一项实施产物：锁定 RSS 精确 artifact 与最小 feature 闭包，在独立 Rust 消费者和真实 PostgreSQL 中验证 Observation 到 Inventory 的原子投影与重放。
- 第一条产品垂直闭环：授权 Windows MDM 注册、可信只读采集、可靠报告、资产投影和授权查询；真实设备验证独立作为 T3。
- 随后形成可核实的原生策略闭环、Rust Agent 执行和升级；按 PRD 并行推进 Mac 与三类采集，并完成软件源与双平台管理。
- 旧设备切换有身份映射、派发停写、未确定任务处置和回退边界；自有 Go 服务与 Agent 迁移后退出，不长期保留两个控制 owner。

目标不以 crate 数、Provider 数或框架数量验收。未发布、未运行和未验证分别记录，experimental 组件可经精确依赖与风险验证用于研发，不等待全体 RSS GA。

## 当前 PR 的边界

本轮更新目标、架构、消费规则与实施方案，不创建空壳业务 crate、不迁移生产数据、不宣称完成组件组合或设备测试。下一步从 [实施路线](202609072231-002-rust-rewrite-roadmap.md) 的 F01 开始；技术取舍见 [架构决策](../architecture/adr/202609072231-001-rust-rss-product-foundation.md)。
