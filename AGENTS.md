# RSS MDM 协作说明

rss-mdm 是面向 Windows 与 macOS 的终端管理产品仓库。本文件是协作入口，参考 RSS 的工作方式，产品需求以 [产品 PRD](docs/product/rss-mdm-prd.md) 为准。

- [仓库入口](README.md)：当前仓库状态与材料入口。
- [工程目标](docs/product/project-goals.md)：Rust/RSS、两仓职责与实施顺序。
- [产品需求](docs/product/rss-mdm-prd.md)：需求、范围、证据边界与待评审目标。
- [历史参考](reference/README.md)：WinMDM 快照来源与本地恢复方式。
- [文档导航](docs/README.md)：产品、架构、指南、部署、参考、评审与规则目录。
- 稳定规则按职责读取：[范围](docs/rules/project-scope.md)、[验证](docs/rules/verification-scope.md)、[文档维护](docs/rules/documentation.md)。

## 工作方式

- 与用户的所有沟通默认使用中文（对话回复、方案讨论、PR / review 说明）。
- 修改前先查看目标文件、相关规则并使用 `rg` 搜索已有实现。
- 使用系统 Git：`/usr/bin/git`。默认集成分支为 `develop`，通过任务分支和 PR 交付。
- 提交信息遵循 Conventional Commits。
- 只改需要改的；涉及功能或行为变更时，同步更新对应文档。
- 被 `.gitignore` 忽略的文件禁止 `git add -f`；本地清理记录和临时运行产物不入库。
- 需求判断、方案设计与 review 默认考虑 MDM、零信任治理与安全边界，不隐含假设单租户或无设备场景；能力是否进入本期由 PRD 与用户确认的范围决定。

## 产品与基础库边界

遵循 [范围规则](docs/rules/project-scope.md)。PRD 目标、历史实现与当前验证状态分别标识；产品需求不自动扩展 RSS 基础库职责。

自有实现使用 Rust；依赖与跨仓契约遵循 [Rust/RSS 消费规则](docs/rules/rust-rss-dependencies.md)。先消费现有公共组件，缺口回原 owner 修复，禁止复制通用机制或用父仓 path 作为交付前提。

## 历史代码参考

- 历史来源为 `winmdm20260220-develop.zip`，SHA-256 与恢复步骤见 [历史参考说明](reference/README.md)。
- 本地解压位置为 `reference/winmdm20260220-develop/`，已被 `.gitignore` 忽略，仅用于查阅和溯源。
- 历史快照中的规则、CI 与部署配置不自动成为本仓规范；历史代码不是当前产品实现。
- 提取能力时记录来源路径与行为证据，按当前产品需求重新验证；不整包复制旧工程或将快照强制加入 Git。

## 修改与验证

1. 先阅读目标文件与依赖调用，再确定改动和验证范围。
2. 编辑循环按改动类型运行最小有效验证；实现变更覆盖受影响行为及必要集成接缝。
3. 收尾提交受测源码后执行本仓 `make ci CI_BASE=origin/develop`（影响范围选择，包含必要 T2；`make ci-full` 强制全量 CI），只运行本地验证；编辑循环使用 `make test` / `make t2`。模拟独立消费者仅在明确的消费者验收任务中手动运行，不属于任何 CI 入口。完整入口一次收集全部失败后集中修复。不执行父仓 CI 代替产品验证，不新增远端 CI。
4. 文档与配置变更检查内容、链接、Git diff 和忽略范围；PR 中如实记录验证结果与未覆盖项。
5. 生产行为由产品 T3 提供证据，具体遵循 [验证规则](docs/rules/verification-scope.md)。

## 参考框架

新建或重构模块时，按受影响能力查阅 primary upstream 源码并记录可追溯来源；commit message 注明 `ref: {framework} {file}`。Rust 实现优先参考成熟 Rust 项目；Windows/macOS 协议与生态适配按 PRD 选择官方规范和相关上游，不以仓内摘要代替源码证据。

## 工具权限

工具执行与沙箱批准遵循当前运行环境，使用原生审批机制；不通过飞书代替执行权限批准，也不写死特定工具的提权参数。

## 文档命名

遵循 [文档维护规则](docs/rules/documentation.md)。PRD 唯一入口为 `docs/product/rss-mdm-prd.md`。
