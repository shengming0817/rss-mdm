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

## 代码布局

采用与 RSS 一致的扁平 Cargo workspace，按能力和消费边界组织：

| 目录 | 职责 |
|---|---|
| `crates/inventory` | `rss-mdm-inventory`：资产字段、coverage 和报告校验；不依赖 PostgreSQL 或示例授权 |
| `crates/inventory-postgres` | `rss-mdm-inventory-postgres`：资产投影、SQL schema 与运行角色/RLS 检查；消费 Inventory 核心和 RSS 公共适配 |
| `crates/app` | `rss-mdm-app`：唯一生产 binary、OIDC/Identity消费、静态资源授权、HTTP与迁移装配 |
| `crates/examples` | `rss-mdm-examples`：fixture CLI、受信操作员 scope、组件装配、配置、时钟及关闭；不是生产 MDM 服务 |
| `tests/inventory-postgres-integration` | 独立真实 PostgreSQL T2 入口；启用 examples 的故障场景支撑 |
| `tests/test_ci.py`、`hack/` | CI 脚本测试与本地验证入口 |
| `fixtures/` | 从仓库根目录运行示例 CLI 的输入样本 |

根目录 `Cargo.toml` 统一管理 workspace members、元数据、依赖和 lint。依赖方向为
app → inventory-postgres/inventory/Identity client；examples → inventory-postgres → inventory；核心和适配均不依赖 examples 或集成测试包。
本仓成员使用 workspace 内部 path，RSS 上游公共库继续固定 Git revision；两者不混同。

根目录 `cargo run --locked -p rss-mdm-examples -- ...` 运行名为 `rss-mdm-fixture` 的示例 CLI。
`make test` 验证全部成员的 T1，`make t2` 运行真实 PostgreSQL 组合，`make ci` 完成全部本地验证。
故障注入矩阵留在 examples 的 `integration` feature 下以访问示例内部状态，不编译进普通示例或产品能力库。

管理员接入与生产命令见 [MDM Identity 接入](docs/guides/202609091600-2343-mdm-identity.md)。
