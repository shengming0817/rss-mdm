# 测试模块

T1 留在能力 crate，验证模型、codec、纯文件逻辑和预算边界。T2 按被验证的能力与消费接缝组织，目录、执行和 affected 使用同一个模块 ID。唯一可执行描述是 [`hack/t2_registry.py`](../../hack/t2_registry.py)：每项声明 Cargo target/Rust 命名空间或 Python 场景、生产输入、测试文件、实际共用的 helper、依赖和排他属性。测试函数由预构建 target 的 nextest listing 发现，不另存函数名名册。

```sh
make ci-plan CI_BASE=origin/develop
make t2
make t2 MODULE=content.http
make t2 MODULE=apple.apns
make t2 MODULE=content.http LIST=1
make t2 MODULE=content.http CASE='<实际发现的完整测试 ID>'
make t2 MODULE=all
make ci-full
```

旧 `SUITE`、`SUITES`、`--suite` 和 `t2Suites` 已删除；不接受旧名称、别名或 fallback。`make ci` 始终只执行快速检查并推荐模块。`CI_FULL=1` 只扩大快速检查，显式 `MODULE=all` 或 CI 入口的 `CI_T2=all` 才选择全部 T2；`ci-full` 同时选择二者。CI 入口仅接受 `CI_T2=none|all`，非法值立即失败。

## 代码职责与复用

| 模块 | 测试职责与代码归属 |
|---|---|
| `installation.migration` | App 正式安装、重放、损坏账本拒绝和 CLI 并发安装；每项使用空库，删除重复双库排列。 |
| `audit.{receipts,integrity,recovery,budget}` | App 通用 Audit 组合、Plain/Ledger、ACK、进程中断和预算；业务模块保留自己事务的原子性证明。 |
| `identity.{local,sso,audit}` | 身份生命周期、联合登录、Identity outbox→Audit worker；不承载资产或任务矩阵。 |
| `authorization.{rules,membership,capacity,initialization,admission}` | 规则与产品用户组、CAS/撤权、真实容量、初始化恢复和准入；路由权限交叉矩阵只在 rules 执行。 |
| `enrollment.{http,recovery}`、`device.{binding,revocation,recovery,admission}` | 注册请求生命周期与回执；设备世代、凭据、来源、绑定竞争和撤销分别归属。 |
| `agent.{registration,reports}` | V3 注册和报告的真实 HTTP/PG 接线；wire 排列仍归 agent-wire T1 和现有 V3 artifact gate。 |
| `inventory.{manual,reader,projection,recovery,process,runtime}`、`examples.cli` | manual/reader 在 Inventory PG；投影、恢复、进程与 CLI 在 examples 的 cfg(test) 模块；App 只验证 intake/runtime 协作。 |
| `api.{diagnostics,identity_context}`、`host.lifecycle` | API envelope、身份上下文和安全诊断；真实宿主启动、readiness、依赖故障与有界关闭。 |
| `assets.{http,queries,sources,group_input}` | 资产授权/事务、查询分页、来源质量、资产成为设备 Group 输入；不重复 Group 完整生命周期。 |
| `group.{persistence,generations}`、`policy.{persistence,recovery}` | 原能力 PG targets 保留，验证各自持久化合同；模型真值表仍是 T1。 |
| `planning.{assets,scope,group_scope,policy,recovery,http}` | 资产时钟与 Group/Scope 发布、引用竞争、assignment、worker 和真实 HTTP 接缝。 |
| `planning.{agent_policy,frequency,remote}` | Agent 策略预览/发布、实际 occurrence、入离组触发、远程冻结目标、分页重启和取消；批量目标只准备合法设备前置。 |
| `compliance.{storage,http,evaluation,recovery,group_input}` | adapter 合同归 Compliance PG；App 负责真实授权、评估、原子发布和 Group applicability 接缝。 |
| `execution.agent.{delivery,content,history,poll,recovery}` | Offer/Start/Result、内容许可、历史分页、取消队列公平性和执行恢复。 |
| `execution.commands.{admission,dispatch,recovery,windows,firewall}` | 命令授权/事务、outbox/relay、恢复诊断、原生结果关联、防火墙配置；普通命令模块不启动 TLS listener。 |
| `resource.{persistence,recovery}`、`software_release.{persistence,recovery}` | 原能力 PG targets 保留，各自验证不可变版本、引用/审批、CAS、回执与 ACK 恢复。 |
| `software.{catalog,http}` | Catalog 借用事务和精确批准归 Software Service target；App 保留 DTO、授权及发布 HTTP 回执接缝。 |
| `content.{http,mirror,gc}` | HTTP 流/Range/文件绑定、受控 HTTPS mirror、引用和 GC 同对象竞争；纯 ZIP/文件逻辑继续是 T1。 |
| `planning.software`、`execution.software.{offer,content,recovery}` | rollout 时间/成功率门与执行版本归 Planning；安装/卸载交付、内容许可、检测、未知/重启/重试归 Execution。 |
| `publication.{winget,brew,mapping,withdrawal,recovery,artifact}` | Software Service 验证外部发布、ring、持久意图和未知结果恢复；artifact-only 不启动 PG。 |
| `planning.resource_archive` | 产品引用和 Resource archive 的同对象竞争，保留 App owner。 |
| `sources.{winget,brew_git,brew_recovery}` | Sources 自有真实 HTTPS/TLS/凭据及 Git/ref/ACK 协议，无产品 PG/Identity。 |
| `native.tls`、`windows.{issuance,enrollment,management,commands,retention,limits}` | TLS 生命周期、签发/注册、会话/nonce、轻量注册→命令、保留期和限流；删除两条完整 native 矩阵。 |
| `apple.{cms,apns,scep,collection,profile,policy,renewal,identity,push,fairness,host}` | 各协议与持久化接缝独立。CMS/APNs 无 PG/Identity；普通原生前置不启动外部 SCEP。 |
| `catalog.contract`、`gateway.admission` | 正式迁移后的全部 SQL catalog 在一个环境核对；真实 nginx 来源/限流/安全头单独验证。 |

App 的 `test_support` 仅在测试编译中可见，复用 Browser、真实身份与授权、合法设备与事实、已发布成员前置、只读审计查询和协议客户端。准备函数不运行另一模块的业务矩阵。软件 artifact peer、definition 和 Git 素材单源位于 `tests/support/software`；组件测试不依赖 App，不为测试扩大生产公开 API。

Identity 用户组与设备 Group 各自归属。Assets 验证资产输入，Planning 验证成员发布如何进入 Scope/Policy，Compliance 验证适用性/版本失效，frequency 验证入离组触发。不同消费接缝各自保留授权、事务和恢复断言。

## affected 与执行证据

选择器对 merge-base、已提交差异、工作区修改、未跟踪和删除输入取并集。独立 T1 文件只贡献 Cargo 检查；独立 T2 文件只选择自身；helper 变化只选择实际消费者；生产变化按登记的输入与消费接缝选择。模块被选中不会继续递归扩大。混合职责的生产文件按整个文件选择，不做 Rust 语义 diff。未知输入、不能可靠判断的 rename/copy、工具链或选择失败保守全量。

Cargo 反向依赖决定编译/Clippy/T1/rustdoc 范围，T2 不继承整个 Cargo 闭包。输出字段为 `cargoFull`、`packages`、`toolTests`、`t2Full`、`modules`、`reasons`。Resource `behavior.rs` 只选 `resource.persistence`；Content T1 和 Scope 模型测试不推荐 T2；Content Range 生产输入选择 HTTP 和两类 Agent task-content 消费接缝。相应 must-select/must-not-select 由工具行为测试固定。

`JOBS` 默认 2，`make t2` 与 `make ci-full` 均接收同一参数，只控制模块并发；模块内测试顺序执行。共享一次构建和一个 PG 服务，按需创建禁止连接的迁移基线。每个独立场景最多占用一个可写克隆，完成即删除；破坏性场景在普通阶段结束后独占并重置同一服务。业务竞争仍在同库同对象内验证。共享的是环境与不可变素材，不是前一测试的结果。

构建、发现和执行复用同一二进制与 Cargo 环境。每个发现的 ignored 业务测试必须有唯一模块归属；辅助子进程入口必须在同一模块描述中声明调用 owner，每个声明恰好发现一个入口；身份准备使用唯一 fixture target。未知 ignored helper 不再按命名空间豁免，函数名仍全部来自发现。空发现、重复归属、错误 CASE、缺依赖、二进制或运行中源码变化都失败。nextest JUnit 必须证明实际运行了唯一精确测试、无忽略/重试/失败；每个 Rust/Python 场景执行预算为 600 秒，Rust 的 nextest 与外层进程截止共同保证有界终止。Python 场景通过受控子进程执行并保留 test.log 完成标记；超时、取消及遗留 Compose 环境均由本轮统一清理。LIST 只要求构建/发现工具，不要求 Docker 等运行依赖。

`artifacts/local-t2/<runId>/` 保存 discovery、逐模块/逐测试结果、准备/执行/清理耗时及资源计数。顶层 result 区分执行与 skipped；LIST 写单独结果，ci-plan 不覆盖正式证据。比较资源消耗应同时查看选择集合、PG/Identity/SCEP 等实际准备次数、并发时间区间和耗时；文件拆分不代表 Rust crate 编译量同比下降。

历史证据最多保留本入口最近 5 轮已确认归属的 runId 目录，保留当前运行及正式 result/LIST 引用的记录。LIST 不删除当前正式结果所指证据；空选择不创建运行目录。未知目录和符号链接不在清理范围。失败 case 的 `log` 指向实际输出，`failureLog` 指向异常栈；控制台同时打印两个路径。
