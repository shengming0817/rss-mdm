# 验证范围

按行为风险选择最小有效验证：T1 验证模型与边界，T2 使用真实依赖验证持久化、权限、协议与恢复，T3 在独立产品任务中验证真实设备与支持矩阵。文档检查内容、链接、来源和 diff。缺依赖或未运行不能宣布通过。

编辑循环使用受影响 package/tests 与 T2；最终 `make ci CI_BASE=origin/develop` 按影响范围运行快速检查，任何模式均不启动 PostgreSQL、网关或 IdP，不隐式执行 T2。`make t2 MODULE=affected CI_BASE=origin/develop` 运行受影响测试模块（裸 `make t2` 默认 affected），`MODULE=planning.http` 等选择专项，`MODULE=all` 选择全部；旧 SUITE/--suite 明确拒绝。执行、发现、affected 共用 `hack/t2_registry.py`，Rust 测试函数通过 nextest 实际发现。`make ci-full` 在同一构建租约内组合全部快速检查和全部 T2，正式候选和浏览器 T3 独立。一次收集失败后集中修复，精确复验失败项及受影响行为，不反复跑完整 CI。不执行父仓 CI 代替产品验证，不新增远端 CI。

CI 直接验证当前工作区，不要求预先提交、clean HEAD 或冷构建。`make ci-plan` 仅预览；选择器比较基线 merge-base 与当前修改，计入未跟踪且非忽略的输入。docs/root Markdown 不贡献 Rust package seed，crate README 可参与 rustdoc。Cargo 与 T2 分别输出 `cargoFull/packages` 与 `t2Full/modules`。Cargo 使用反向依赖闭包；独立 T1 文件不选 T2，独立 T2 文件只选所属模块，helper 只选直接消费者。生产输入按模块声明的实际消费接缝选择，多个输入取并集。包级 manifest 按可确定的依赖范围选择；lock、工具链、未知路径、无法可靠识别的 rename/copy 或分析失败保守全量；存在脏文件本身不触发全量。CI 在选择前与执行后核对当前文件集合、内容及状态，运行期间输入变化则失败，避免将旧测试结果用于新源码。

选中 Rust 包后检查当前 normal/all-features metadata 与依赖来源和必要 T1；持久化、SQL、权限变化必须另跑对应 PG T2，协议变化必须另跑对应协议 T2，公共鉴权、迁移和装配扩大覆盖。纯模型与文档按接缝风险选择，不以 Rust 的 App 反向依赖闭包直接代替 T2 路径映射；不克隆独立消费者、不重新打包逐 crate、不另起隔离冷构建或百万容量脚手架。功能预算边界仍用小输入或算术边界验证；规模与性能承诺须另立有场景的验证任务。

Make 的正式构建、测试与 CI 由统一启动器持有 worktree/target 独占租约；显式 target 和关闭池只改变目录选择，不关闭租约。正式 CI/T2 脚本拒绝无租约执行，ci-plan 仅预览。配置、直接 Cargo 边界及故障恢复见[本地开发](../guides/local-development.md#构建槽位与缓存)。缓存与工具链记录是诊断信息，不是通过证明。

artifacts/local-ci 中 selection/result 记录选中 gate、命令及 passed/failed/skipped；推荐 T2 与实际执行分开记录，快速检查通过不代表集成验证通过。独立 T2 结果位于 artifacts/local-t2，空选择明确为 skipped/no-modules-selected；缺依赖、零测试和 ignored 伪绿必须失败。skipped 不表示通过，affected 不称为全量。计划不覆盖正式结果，正式执行清理本入口自有旧记录。源码版本、lock 与工具链可作普通运行记录，不作“干净提交”准入。

真实候选用一次正式 OCI 构建及随附部署输入验证安装、启动和认证，不依赖 matching checkout。候选 smoke/浏览器不替代真机；发布声明绑定实际 OS/架构、注册方式、权限、依赖、故障范围及结果。未测组合如实保留，性能、RPO/RTO 不继承历史数字。

开发/T2 环境按 worktree 隔离，独立于共享 target 槽位；一次 T2 运行只使用一个 PG 服务；普通模块按 JOBS 并发（默认 2），模块内测试顺序执行。正式迁移基线禁止连接，单个测试克隆独立可写数据库，完成即删除，可写测试库数量不超过 JOBS。实例级破坏性模块在普通阶段排空后独占同一服务，每个场景重置服务并作废旧基线，不另建一套故障实例。安装场景始终使用空库。同对象竞争在同一库内用同步点验证。平台工具、Identity、SCEP、Keycloak 和 HTTPS/Git 按模块需要准备。详见[测试模块](../guides/test-modules.md)。
