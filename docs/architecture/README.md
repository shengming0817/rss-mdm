# 架构设计

本目录承载产品系统边界、通道与 Agent 契约、数据模型、执行和恢复设计。工程基线见 [Rust/RSS 重写决策](adr/202609072231-001-rust-rss-product-foundation.md)；具体产品协议与生产参数随实施冻结。

设计须关联 [PRD](../product/rss-mdm-prd.md) 的需求编号，说明约束、依赖、兼容与迁移、失败恢复及验证方式；不得将历史 Go 类型和表结构直接视为新契约。

影响长期边界的取舍记录在 [adr/](adr/README.md)。产品与基础库职责遵循 [范围规则](../rules/project-scope.md)。

- [#2350 + #2351 Windows 注册与管理通道实施计划](202609111146-2350-windows-enrollment-management-plan.md)
