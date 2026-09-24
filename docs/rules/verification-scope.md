# 验证范围

按行为风险选择最小有效验证：T1 验证模型与边界，T2 使用真实依赖验证持久化、权限、协议与恢复，T3 在独立产品任务中验证真实设备与支持矩阵。文档检查内容、链接、来源和 diff。缺依赖或未运行不能宣布通过。

编辑循环使用受影响 package/tests 与 T2；最终 `make ci CI_BASE=origin/develop` 按影响范围运行，`make ci-full` 强制全量。一次收集失败后集中修复，精确复验失败项及受影响行为，不反复跑完整 CI。不执行父仓 CI 代替产品验证，不新增远端 CI。

CI 直接验证当前工作区，不要求预先提交、clean HEAD 或冷构建。`make ci-plan` 仅预览；选择器比较基线 merge-base 与当前修改，计入未跟踪且非忽略的输入。docs/root Markdown 不贡献 Rust package seed，crate README 可参与 rustdoc。manifest/lock、工具链、CI 配置、rename/copy、未知路径或分析失败保守全量；存在脏文件本身不触发全量。

选中 Rust 包后检查当前 normal/all-features metadata 与依赖来源、必要 T1/T2；不克隆独立消费者、不重新打包逐 crate、不另起隔离冷构建或百万容量脚手架。功能预算边界仍用小输入或算术边界验证；规模与性能承诺须另立有场景的验证任务。

Make 默认缓存行为由 Makefile/hack 持有。需要隔离 worktree 产物时显式设置 CARGO_TARGET_DIR/SCCACHE_DIR；本次规则不改变默认缓存布局。缓存与工具链记录是诊断信息，不是通过证明。

artifacts/local-ci 中 selection/result 记录选中 gate、命令及 passed/failed/skipped；skipped 不表示通过，affected 不称为全量。计划不覆盖正式结果，正式执行清理本入口自有旧记录。源码版本、lock 与工具链可作普通运行记录，不作“干净提交”准入。

真实候选用一次正式 OCI 构建及随附部署输入验证安装、启动和认证，不依赖 matching checkout。候选 smoke/浏览器不替代真机；发布声明绑定实际 OS/架构、注册方式、权限、依赖、故障范围及结果。未测组合如实保留，性能、RPO/RTO 不继承历史数字。
