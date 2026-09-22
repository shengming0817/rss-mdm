# 验证范围

验证按改动风险选择，不以数量或静态记录代替行为证明。

- 文档与配置：检查内容、链接、引用、diff 和忽略范围；本地材料不误入 Git。
- T1：验证模型、状态机和组件行为。
- T2：验证真实数据库、消息、存储、协议适配等依赖接缝。
- T3：在产品仓以独立、限定范围的 issue/PR 验证真实设备上的业务闭环、权限、升级和故障恢复；明确需求、设备矩阵、输入输出与故障范围。

F01 的验证入口为本地 `make ci`，模型测试为 `make test`，真实 PostgreSQL 组合为 `make t2`。本期不建立远端 CI；不执行父仓库 CI 充当产品验证。结果绑定受测 HEAD，未完成的 gate 不得宣布通过。

Make 入口通过 Git common directory 将所有本仓 worktree 的 Cargo 产物统一写入主 checkout 的
`target/`；可选 sccache 位于主 checkout 的 `.cache/sccache/`，不与 RSS 或其它产品仓共享。
显式 `CARGO_TARGET_DIR`、`SCCACHE_DIR` 仍可覆盖本地默认值；隔离消费验证保留独立临时目录。

发布记录绑定版本、OS/架构、注册方式、权限与外部依赖、实际请求和结果。模拟终端、组件测试、历史代码或厂商能力不替代真实产品证据；未测试的组合不得宣称支持。

性能容量、兼容窗口与 RPO/RTO 在发布前按场景冻结并验证，不沿用冲突的历史指标。未覆盖的验证项如实记录。

可选缓存不可用（无 Git 元数据、目录无法创建、sccache 执行失败）时直接执行 rustc；
sccache 失败最多直接重试一次，最终保留 rustc 退出码，编译错误可能输出两次。
默认 socket 位于有效 `SCCACHE_DIR` 内；显式 `SCCACHE_SERVER_UDS` 覆盖时由调用方保证
服务与缓存配置一致，修改同一服务的缓存配置需重启该服务。

## 本地 CI 影响范围

`make ci` 默认比较 `CI_BASE=origin/develop` 与受测 HEAD 的 merge-base，在任务分支按影响范围
运行；`develop` 分支、`make ci-full` 或 `CI_FULL=1` 执行全部 gate。缺失基线、rename/copy、
Cargo manifest/lock、工具链、CI 脚本/配置、未知路径、未知删除或分析异常保守回退全量。
正式 `make ci`/`make ci-full` 会关闭继承的 `CI_PLAN`，只有 `make ci-plan` 启用预览。
`make ci CI_BASE=<ref>` 可指定基线；`make ci-plan` 只输出计划，不运行 gate，也不产生通过证明。
应先提交受测源码；脏工作区计划回退全量，正式执行的 HEAD/clean identity gate 仍会失败。

`hack/ci-impact.py` 参考 RSS 同名选择器，以 Cargo all-features metadata 的 normal/dev/build/
optional 反向依赖闭包选择包。已识别根文档、docs 与技能 Markdown 不贡献 package seed；混合
文档与源码按源码闭包选择。crate 内 README 可能参与 rustdoc，仍作为所属包输入。
check/clippy/T1/doc-test 使用选中包；T2 按 `hack/ci.py` 的 gate 映射选择，
包含 Cargo 图外的应用 schema、迁移和 fixture 输入。新 gate 未映射时，有包变更即保守执行。
选中任何 Rust 包仍执行真实产品的隔离构建与来源/feature 图验证；advisories 仅在全量模式运行。
模拟独立消费者不属于 `make ci`、`make ci-full` 或 `make ci-plan`，仅在明确的消费者验收任务中显式运行。纯文档或无变更跳过 Rust/T2 和产品隔离构建，但保留脚本测试、fmt、pin 与 HEAD 身份检查。

`artifacts/local-ci/selection.json` 记录正式执行的基线、merge-base、HEAD、选择原因、包和所有 gate 的命令或内部检查说明；
计划模式仅写 `plan.json`，不覆盖正式执行的 selection/result。正式执行开始时只清理 CI gate 自有的旧日志与 metadata/tree；
手动消费者的验收产物不归 CI 清理，CI 结果也不记录消费者的 passed/skipped；
`result.json` 的 gates 区分 passed/failed/skipped，skipped 不代表通过。完整入口始终收集所有
选中 gate 的失败后再返回非零；不得把 affected 结果描述为全量验证或产品 T3。

选择器未知内部异常使用 `selector-internal` 原因，并在 stderr 记录阶段和异常类型，不记录异常原文。
runner 分离读取 stdout JSON 与 stderr 诊断，将诊断保存在选择记录的 diagnostic 字段；已知错误原因保持不变。
