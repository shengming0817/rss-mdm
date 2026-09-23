# 开发与使用指南

本目录承载开发环境、产品接入、管理员操作与故障诊断指南。F01 提供限定范围的本地运行入口。

新增指南明确适用版本、前置条件、执行步骤和可观察结果；部署与升级操作归 [deployment](../deployment/README.md)，协作约定归 [AGENTS.md](../../AGENTS.md)。

- [F01 本地 Inventory](202609080000-2346-local-inventory.md)

- [Windows MDM V1 编解码与关联](202609080000-2349-windows-mdm-codec.md)：协议配置、有界接口与 T1 证据边界。

- [Resource 与 WinGet/Brew 后端元数据](202609090000-2383-resource-sources.md)：冻结版本、受控协议/模板、本地 Git 与独立消费。

- [Group 类型化规则与成员差分](202609090000-2380-group-core.md)：纯核心 API、未知/完整性语义、历史对照与独立消费证据。
- [MDM Identity 接入](202609091600-2343-mdm-identity.md)

- [Enrollment 与审计](202609090001-2347-enrollment-audit.md)（#2347/#2350）

- [设备身份与报告边界](202609100445-2348-device-principal.md)（#2348）

- [Windows 注册与管理通道](202609111146-2350-windows-enrollment-management.md)（#2350/#2351）：配置、签发恢复、mTLS 与首次 SyncML 认证，T3 独立验收。

- [Windows 资产采集与查询](202609120000-2352-windows-inventory.md)（#2352/#2353）：CollectionRun、恢复、质量和查询契约。
- [Group PostgreSQL](202609120000-2387-group-postgres.md)：持久输入、版本 CAS、原子事件、恢复与独立 PG 消费。

- [Policy / Resource / 发布持久化](202609132008-2388-2389-backend-persistence.md)：三个独立 PG adapter、公开产物、源发布/撤回与原身份恢复。

- [授权管理与计划闭环](202609161020-2390-management-plans.md)：真实管理员权限、资产/组/Scope 组装、预览保存和私有源审批。

- [#2363 持久化 MDM 授权](202609200002-2363-authorization.md)

- [统一资产、Manual 与授权搜索](202609210000-2463-unified-assets.md)（#2463）。
- [设备状态核实任务](202609210000-2465-command-operations.md)：授权受理、原生投递、实际观察及恢复。

- [Windows Domain 防火墙配置](202609220000-2466-windows-firewall.md)（#2466）：固定 DDF、冻结计划、统一原生投递及独立设备级观察。
- [Agent V1 注册与报告接入](202609220000-2467-agent-wire-access.md)：严格 wire、全新安装、凭据绑定、持久报告与独立 artifact 消费证明。

- [#2471 Apple 手动注册、采集与 Profile](202609230000-2471-apple-management.md)
