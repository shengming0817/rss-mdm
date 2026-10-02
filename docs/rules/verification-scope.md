# 验证范围

T1 提供模型与边界证据；T2 使用真实依赖提供持久化、权限、协议与恢复证据；T3 在独立产品任务中验证真实设备与支持矩阵。缺依赖或未运行不能宣布通过。

`make ci CI_BASE=origin/develop` 按影响范围运行快速检查，任何模式均不启动 PostgreSQL、网关或 IdP，不隐式执行 T2。`make t2 MODULE=affected CI_BASE=origin/develop` 运行受影响测试模块（裸 `make t2` 默认 affected），`MODULE=planning.http` 等选择专项，`MODULE=all` 选择全部；旧 SUITE/--suite 明确拒绝。执行、发现、affected 共用 `hack/t2_registry.py`，Rust 测试函数通过 nextest 实际发现。`make ci-full` 在同一构建租约内组合全部快速检查和全部 T2，正式候选和浏览器 T3 独立。本仓结果不由父仓 CI 代替；不新增远端 CI。

CI 直接验证当前工作区，不要求预先提交、clean HEAD 或冷构建。`make ci-plan` 仅预览；选择器比较基线 merge-base 与当前修改，计入未跟踪且非忽略的输入。docs/root Markdown 不贡献 Rust package seed，crate README 可参与 rustdoc。Cargo 与 T2 分别输出 `cargoFull/packages` 与 `t2Full/modules`。Cargo 使用反向依赖闭包；独立 T1 文件不选 T2，独立 T2 文件只选所属模块，helper 只选直接消费者。生产输入按模块声明的实际消费接缝选择，多个输入取并集。包级 manifest 按可确定的依赖范围选择；lock、工具链、未知路径、无法可靠识别的 rename/copy 或分析失败保守全量；存在脏文件本身不触发全量。CI 在选择前与执行后核对当前文件集合、内容及状态，运行期间输入变化则失败，避免将旧测试结果用于新源码。

PG T2 提供持久化、SQL、权限与事务证据；协议 T2 提供真实 HTTP/TLS、身份、回执与恢复证据。App 反向依赖闭包不能直接代替 T2 路径映射。功能预算边界使用小输入或算术边界；规模与性能承诺由有明确场景的独立验证任务提供证据。

Make 的正式构建、测试与 CI 由统一启动器持有 worktree/target 独占租约；显式 target 和关闭池只改变目录选择，不关闭租约。正式 CI/T2 脚本拒绝无租约执行，ci-plan 仅预览。配置、直接 Cargo 边界及故障恢复见[本地开发](../guides/local-development.md#构建槽位与缓存)。缓存与工具链记录是诊断信息，不是通过证明。

artifacts/local-ci 中 selection/result 记录选中 gate、命令及 passed/failed/skipped；推荐 T2 与实际执行分开记录，快速检查通过不代表集成验证通过。独立 T2 结果位于 artifacts/local-t2，空选择明确为 skipped/no-modules-selected；缺依赖、零测试和 ignored 伪绿必须失败。skipped 不表示通过，affected 不称为全量。计划不覆盖正式结果，正式执行清理本入口自有旧记录。源码版本、lock 与工具链可作普通运行记录，不作“干净提交”准入。

真实候选用一次正式 OCI 构建及随附部署输入验证安装、启动和认证，不依赖 matching checkout。候选 smoke/浏览器不替代真机；发布声明绑定实际 OS/架构、注册方式、权限、依赖、故障范围及结果。未测组合如实保留，性能、RPO/RTO 不继承历史数字。

开发/T2 环境按 worktree 隔离，独立于共享 target 槽位。`JOBS` 限制独立 case 的完整生命周期，默认 2；模块内也允许并发。普通兼容业务按对象/主体或合法专用租户隔离观察范围，共用可写库；DDL、库内权限和损坏材料使用一次性库，安装始终使用空库；共享角色和停库故障使用独立 PG 实例。故障实例恢复检查成功后可复用，失败或不确定则隔离，仅为后续 case 建立替代环境，不重跑掩盖原失败。数据库数量不由 case、模块或 worker 数决定。稳定身份、内容与签名按兼容环境准备；公共 worker 属于运行环境，精确消费者故障属专用观察域。复用需验证同库重复、换序与实际并发重叠，同对象竞争用同步点。平台工具、Identity、SCEP、Keycloak 和 HTTPS/Git 按实际需要准备。详见[测试模块](../guides/test-modules.md)。
