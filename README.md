# rss-mdm

面向 Windows 与 macOS 的企业私有化终端管理产品仓库。默认分支为 `develop`。F01 提供基于 RSS 的独立 Rust Inventory 组合和本地 CI；其它产品目标仍按路线分期实现。

- [项目目标](docs/product/project-goals.md)：基于 RSS 的 Rust 服务端与独立 Rust Agent，保留现有前端。
- [实施路线](docs/product/202609072231-002-rust-rewrite-roadmap.md)：第一项消费验证与真实 Windows 只读闭环。
- [产品需求](docs/product/rss-mdm-prd.md)：v0.2 评审草案、需求与验收目标。
- [文档导航](docs/README.md)：产品、架构、指南、部署、参考、评审与稳定规则。
- [协作规则](AGENTS.md)：开发与交付约定。
- [历史参考](reference/README.md)：本地 WinMDM 快照来源与恢复方式，代码由 Git 忽略。

历史能力与产品目标不代表本仓已经实现或完成验证。

- [F01 本地运行与验证](docs/guides/202609080000-2346-local-inventory.md)：固定 Git 依赖、迁移、fixture 接收、投影与恢复。
