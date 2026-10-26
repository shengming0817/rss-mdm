# 测试模块

T1 留在能力 crate，验证模型、codec、纯文件逻辑和预算边界。T2 按被验证的能力与消费接缝组织，目录、执行和 affected 使用同一个模块 ID。唯一可执行描述是 [`hack/t2_registry.py`](../../hack/t2_registry.py)：每项声明 Cargo target/Rust 命名空间或 Python 场景、生产输入、测试文件、实际共用的 helper、运行所需材料、数据库生命周期和数据范围。测试函数由预构建 target 的 nextest listing 发现，不另存函数名名册。

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

## 从被测动作选择前置

先按[验证规则的设计顺序](../rules/verification-scope.md#测试设计)明确风险、动作与层级，再选前置和隔离。以下是边界示例，不是永久用例名册；实际模块、依赖和当前可执行策略仍以 registry 与 runner 为准。

| 被测动作 | 最小前置与必须保留的证明 |
|---|---|
| 普通查询、分页 | 用兼容 baseline 加最少可辨识记录，直接预置合法设备/资产，无需逐条注册或重跑发布流程。经过实际查询角色与接口，检查非空必需结果、分页内容及不可见的异租户哨兵。 |
| 注册专项 | 准备合法租户、主体与必需凭据，走真实注册入口；核对凭据绑定、拒绝路径及落库/回执副作用。只有属于该流程的初始化或签发接缝才随之执行，不捎带其它业务矩阵。 |
| CA 恢复 | 普通非签发消费者使用合法证书和注册种子，保留真实签名验证；只有实际签发消费者需要在线 CA；恢复专项显式准备冷备、触发提升/故障并验证恢复后的签发及信任连续性，不让所有消费者隐式跑恢复。 |
| 事务 / RLS | 可用受控 SQL 预置合法行；被测动作使用实际运行角色、认证上下文与事务，核对原子提交/回滚和跨租户拒绝及无副作用。管理员造数不能替代最小权限断言，租户设置不能使超级用户受 RLS 约束。 |
| 需求退出 | 根据已接受的产品退出决定，核对是否仍有公开兼容或存量消费承诺；清理失效用例与登记，只为仍有效风险保留证明，不为凑后继迁成等量 T1。当前模块删除的执行器限制见下节 affected 说明。 |

前置中的租户容量、外键、状态/世代、凭据来源及签名字节必须满足真实消费者不变量。复用前核对兼容性；涉及权限修改、密钥轮换、精确消费或损坏材料时扩大必要隔离。辅助准备失败应直接暴露，不能靠绕过认证、RLS 或把目标动作预先执行完来缩短测试。

## 代码职责与复用

下表概述当前能力归属，不规定固定用例数量或历史模块排列；完整模块集合和执行入口查询 registry。

| 模块 | 测试职责与代码归属 |
|---|---|
| `installation.migration` | App 正式安装、重放、损坏账本拒绝和 CLI 并发安装；安装使用空库。 |
| `installation.registry` | 租户 CRUD、回执、容量竞争、first-use 与 RLS；从兼容 product baseline 克隆独立库，实际迁移动作仍由专项显式调用。 |
| `audit.{receipts,integrity,recovery,budget}` | App 通用 Audit 组合、Plain/Ledger、ACK、进程中断和预算；业务模块保留自己事务的原子性证明。 |
| `identity.{local,sso}` | 身份生命周期、联合登录及同事务审计；不承载资产或任务矩阵。 |
| `authorization.{rules,membership,capacity,initialization,admission}` | 规则与产品用户组、CAS/撤权、真实容量、初始化恢复和准入；路由权限交叉矩阵只在 rules 执行。 |
| `enrollment.{http,recovery}`、`device.{binding,revocation,recovery,admission}` | 注册请求生命周期与回执；设备世代、凭据、来源、绑定竞争和撤销分别归属。 |
| `agent.pki` | registration owner 的签发授权、真实固定 step-ca/JWK CSR 绑定、365/3650 天配置、双阶段审计、原 CA 数据库恢复及 TLS 用途隔离。 |
| `agent.{registration,reports}` | V1 注册和报告的真实 HTTP/PG 接线；wire 排列仍归 agent-wire T1 和现有 V1 artifact gate。 |
| `inventory.{manual,reader,projection,recovery,process,runtime}`、`examples.cli` | manual/reader 在 Inventory PG；投影、恢复、进程与 CLI 在 examples 的 cfg(test) 模块；App 只验证 intake/runtime 协作。 |
| `api.{diagnostics,identity_context}`、`diagnostics.http`、`host.lifecycle` | API envelope、身份上下文；授权运行诊断的真实任务、依赖、投影和积压；真实宿主启动、readiness、依赖故障与有界关闭。 |
| `assets.{http,queries,sources,group_input}` | 资产授权/事务、查询分页、来源质量、资产成为设备 Group 输入；不重复 Group 完整生命周期。 |
| `group.{persistence,generations}`、`policy.{persistence,recovery}` | 原能力 PG targets 保留，验证各自持久化合同；模型真值表仍是 T1。 |
| `planning.{assets,scope,group_scope,policy,recovery,http}` | 资产时钟与 Group/Scope 发布、引用竞争、assignment、worker 和真实 HTTP 接缝。 |
| `planning.{agent_policy,frequency}` | Agent 策略预览/发布、实际 occurrence 与入离组触发。 |
| `compliance.{storage,http,evaluation,recovery,group_input}` | adapter 合同归 Compliance PG；App 负责真实授权、评估、原子发布和 Group applicability 接缝。 |
| `execution.agent.{delivery,content,history,poll,recovery}` | Offer/Start/Result、内容许可、历史分页、取消队列公平性和执行恢复。 |
| `execution.commands.{admission,dispatch,recovery,windows,onboarding}` | 命令授权/事务、outbox/relay、恢复诊断、原生结果关联与 Agent onboarding；普通命令模块不启动 TLS listener。 |
| `resource.{persistence,recovery}`、`software_release.{persistence,recovery}` | 原能力 PG targets 保留，各自验证不可变版本、引用、CAS、回执与 ACK 恢复。 |
| `software.{catalog,http}` | Catalog 借用事务与版本状态归 Software Service target；App 保留 DTO、授权、直接启用与发布 HTTP 回执接缝，不保留已退出的软件审批流程要求。 |
| `content.{http,mirror,gc}` | HTTP 流/Range/文件绑定、受控 HTTPS mirror、引用和 GC 同对象竞争；纯 ZIP/文件逻辑继续是 T1。 |
| `planning.software`、`execution.software.{offer,content,recovery}` | rollout 时间/成功率门与执行版本归 Planning；安装/卸载交付、内容许可、检测、未知/重启/重试归 Execution。 |
| `publication.{winget,brew,mapping,withdrawal,recovery,artifact}` | Software Service 验证自托管发布、ring、持久意图和未知结果恢复；artifact-only 不启动 PG。 |
| `planning.resource_archive` | 产品引用和 Resource archive 的同对象竞争，保留 App owner。 |
| `sources.{winget,brew_git,brew_recovery}` | Sources 自有真实 HTTPS/TLS/凭据及 Git/ref/ACK 协议，无产品 PG/Identity。 |
| `windows.{issuance,enrollment,management,commands,retention,limits}` | 受信网关证书证据、签发/注册、会话/nonce、轻量注册→命令、保留期和业务限流；公网 TLS 由 Nginx 接缝验证。 |
| `apple.{cms,apns,scep,collection,profile,policy,renewal,identity,push,fairness,host,commands,users,ddm,status}` | 各协议与持久化接缝独立。CMS/APNs 无 PG/Identity；普通原生前置不启动外部 SCEP。 |
| `installation.storage`、`gateway.admission` | 产品安装准入与恢复由前者验证；真实 nginx 来源/限流/安全头由后者验证。 |

App 的测试实现统一放在 `crates/app/tests/`，按业务 owner 分目录；`src/` 只保留 `cfg(test)` 接入和必要测试钩子。现有 Rust 命名空间与 MODULE ID 保持独立，不要求物理路径包含 `t2`。目录按当前 owner 维护，不由历史拆分方式决定测试保留数量。

App 的 `tests/support` 仅在测试编译中可见，复用 Browser、真实身份与授权、合法设备与事实、已发布成员前置、只读审计查询和协议客户端。准备函数不运行另一模块的业务矩阵。公共 helper 入口只持有模块声明与导入，由现有编译及测试发现检查装配。实现文件只登记直接测试调用；准备 helper 的间接调用不展开为其业务调用方，新增 fixture 导出不触发全部身份业务。日常选择只匹配改动输入，不沿测试、helper 或业务依赖递归展开。定期完整 T2 沿用既有安排。Planning、InventoryRuntime 和 Assets 的专用准备代码归各自测试目录；仅实际跨 owner 消费的素材放公共 support。软件 artifact peer、definition 和 Git 素材单源位于 `tests/support/software`；组件测试不依赖 App，不为测试扩大生产公开 API。

Identity 用户组与设备 Group 各自归属。Assets 验证资产输入，Planning 验证成员发布如何进入 Scope/Policy，Compliance 验证适用性/版本失效，frequency 验证入离组触发。不同消费接缝各自保留授权、事务和恢复断言。

## affected 与执行证据

选择器对 merge-base、已提交差异、工作区修改、未跟踪和删除输入取并集。独立 T1 文件只贡献 Cargo 检查；独立 T2 文件只选择自身；业务断言 helper 变化选择直接验证者，公共准备由现有 owner 专项证明；生产变化按当前登记的直接行为与被测接缝选择。模块被选中不会继续递归扩大。登记描述与选择机制分离，基线完整版本树仅导出描述，不运行历史 selector；执行描述和业务输入变化选模块，选择机制变化由现有工具行为测试证明。manifest/lock 仅选择 Cargo 检查，不推导业务 T2。混合职责的生产文件按直接登记选择，不做 Rust 语义 diff。Cargo 已确认归属的生产文件可以没有 T2 映射，此时仍执行受影响的编译、Clippy、T1 和契约检查。发现、调度、日志和汇总由工具测试持有；真实执行、隔离或故障变化在同一 registry 的 `REPRESENTATIVE_INPUTS` 声明最小现有模块集合，fixture/profile、平台前缀及准备依赖不用于生成业务模块集合。可识别 rename/copy 的两端使用当前输入登记，旧映射不恢复已删除的扩散规则。未登记的非生产输入、不可用基线、异常或非法选择结果必须失败，由实现者修复归属或分析问题；不通过隐式全量、静默跳过或手工 MODULE 掩盖。

模块职责变化使用两版 registry 和实际文件/target 事实。`removedModules` 记录消失的模块、载体删除或当前 T1/T2 归属；不维护 `replaces`、旧名称或永久退出名册。仍存在或移动后的测试文件必须有当前测试 owner，仅 support/production 通配不能承接。Python scenario 删除后，其执行文件也须删除或由当前模块直接承接。需求退出依据在 issue/PR，机器检查不替代业务判断。

`ownershipChecks` 是从本次删除、build/selector/child 变化或纯测试装配入口变化派生的临时发现计划。Cargo metadata 确认 target 是否仍存在；现存 target 按当前 features 用 nextest 编译/发现，检查每个 ignored 测试的唯一当前 owner，零 ignored 允许退出。目标已删除无需构建，构建或发现失败不能冒充删除成功。`make ci` 与 affected T2 入口执行检查，即使业务模块空选也不跳过；不启动数据库、Identity 或业务测试函数。`ci-plan` 仅展示要求，未执行发现不表示校验通过。

迁移列表与执行机制分离。局部 schema 选择直接存储证明，公共安装/catalog/权限契约由对应专项证明；不从源码消费者反推 schema 的下游业务集合。公共模型、wire、查询与预算不触发所有消费产品回归。仅登记说明或输入归属元数据变化执行工具验证，真实输入变化使用当前登记，执行策略变化选择所属模块。日常 affected 不叠加定期完整 T2，周期回归沿用既有安排。

`MODULE=affected` 始终使用直接选择结果，不受 `CI_FULL`/`CI_T2` 环境变量扩展；显式 `MODULE=all` 和 `ci-full` 保留给完整回归。公共编译配置变化只扩大 Cargo 检查。

Cargo 反向依赖决定编译/Clippy/T1/rustdoc 范围，T2 不继承 Cargo 闭包，manifest/lock 变化不自动推荐业务 T2；依赖升级按任务通过 `MODULE` 显式运行必要专项。成功输出包含 `status=selected`、`cargo.mode/packages`、`t2.mode/modules`、`toolTests`、`reasons`、`removedModules` 和 `ownershipChecks`；失败输出为 `status=failed` 与 `error`，进程非零退出。Resource `behavior.rs` 只选 `resource.persistence`；Content T1 和 Scope 模型测试不推荐 T2；Content Range 生产输入选择 HTTP 和两类 Agent task-content 消费接缝。相应 must-select/must-not-select 由工具行为测试固定。

`JOBS` 默认 2，只控制同时运行的独立 case 数量，预算覆盖准备、执行和清理；模块归属不构成互斥。数据库数量由状态影响范围决定，不按模块或 worker 分库：

| 策略 | 生命周期与隔离 |
|---|---|
| `reuse` | 同一兼容 profile 使用同一可写数据库，允许同库并发。普通业务隔离对象与可变主体；全租户查询、配额、水位、审计头故障和精确消费者控制使用合法专用租户或租户对。 |
| `fresh` | DDL、表权限、目录和持久材料损坏使用一次性库，完成即删除；正式安装使用空库，其余从禁止连接的迁移基线克隆。 |
| `instance` | 共享角色和停库故障使用独立 PG 服务，该服务内一次一个 case，与普通 PG 并行。成功后核对角色和设置；失败或恢复不确定则标记隔离，为后续 case 重建，保留原失败。 |
| 无 PG | 不启动 PostgreSQL，文件、端口、Git、HTTPS peer 等资源仍由各 case 持有。 |

模块默认策略与少量 case 例外一起解析；过期例外、重叠策略、非法生命周期和冲突的消费者归属在服务启动前失败。`LIST=1` 输出发现的完整测试 ID 和实际策略。

准备数据按前述设计流程选择最小合法状态；不要求全体租户经正式 CLI 或每次固定创建独立账户/会话。对象命名空间、主体和租户隔离由读写范围决定；修改权限、密码或会话的测试只操作自己的主体。稳定 bootstrap、身份、内容仓及签名材料在兼容环境内复用，会话按有效期与场景需要签发。普通 Agent、Windows 和 Apple 业务前置由状态 owner 准备当前注册与真实证书；注册、签发专项保留完整协议。软件前置由 Resource/Software owner 写入合法 active/enabled 状态，并保留真实内容上传、校验及事务期间的内容 pin；发布专项在其用例内执行正式发布链。上传前置使用现有共享内容目录中的测试专属文件锁协调，正文带资源身份以隔离读取；业务 API 的并发竞争不受准备锁影响。

**当前执行器边界**：迁移基线不预注册本轮全部租户。case 获准进入 `JOBS` 后，准备所属租户与必要跨租户哨兵，通过已有 `public.create_new_tenant` 在一个事务内完成最小合法登记。兼容数据库只初始化一次管理身份；稳定主体与真实有效会话在兼容环境内复用；需独立主体的已准入 case 合并使用 Identity 的公开账户 provisioner，保留正常密码 KDF，不复制 Identity 私有存储。`MDM_CASE_CONTEXT` 只接受当前 actors 列表格式，Python 与 Rust 同步验证；不存在旧 context 字段的兼容读取。账号、配置设备密钥数量和特殊 CA 材料由模块／case 策略声明。

准备、执行、清理共同占用 `JOBS`，没有全体账号准备完才进入首个测试的屏障。普通 Agent、Windows 和 Apple 业务直接准备当前注册、真实离线证书和合法 trust/CRL；不启动在线 CA，也不执行在线准入、签发或发布前置。测试装配使用现有状态 owner 的事务种子，真实生产宿主在开放监听前仍执行在线准入。普通 worker 仅启动实际使用的领域后台能力。完整产品 schema 清单由 App 的 Database 准入检查一次；能力构造只验证自身合同。通道 fixture 直接挂现有领域路由，不经完整 App/Flow 装配，连接池由宿主资源栈唯一关闭。注册、签发、SCEP、撤销发布、轮换和恢复专项按实际被测接缝保留在线 provider；其余前置仍用种子。普通 Apple 保留真实 TLS、Authenticate 和 TokenUpdate；Windows 管理前置使用已验证的当前凭据种子。作用域准备在所属模块内解析，资源版本由存储所属模块编码，不从 App 复制内部格式。

普通后台任务由测试持有实际领域消费者，在专用租户内等待和观察自己的结果；完整 `rss-mdm serve` 只用于产品宿主与真实 HTTP 装配专项。停止和恢复由用例自己的资源栈负责，不得跨域修改数据或文件。管理员 SQL 必须显式限定归属；租户设置不能使超级用户受 RLS 约束。负面授权测试继续保留跨租户哨兵和副作用检查。

复用资格必须包含同库 A→B→A、换序、同租户不同对象实际重叠及异租户同步写入；关键同对象竞争使用同步点。故障不得靠隐式换库重试隐藏。

正式资格入口为 `make t2 MODULE=all REUSE_PLAN=/absolute/reuse-plan.json JOBS=2`。计划取 LIST 中实际发现的完整 ID，格式为 `{"objects":["A的ID","B的ID"],"tenants":["C的ID","D的ID"]}`：四项必须同 profile、`reuse`、Rust 用例，A/B 为 objects，C/D 为 tenant 或 pair。建议 A/B 选择注册与内容/执行，C/D 选择主体授权与全租户观察。执行器在一次环境生命周期内固定运行 A→B→A、B→A→B，再并发 A/B 与 C/D；所有调用重新分配对象和主体，保持同一物理 PG/数据库。并发组在两个实际 Rust 用例进入 context 后会合，核对执行区间重叠及租户关系。`reuse.json` 和逐调用 result 保存计划、顺序、数据库与运行证据；未到达会合、换库或任何业务断言失败均不能通过。该代表场景资格不替代全量 T2。

T2 PG 的连接容量按 `JOBS` 预算准备：每个活动 case 预留 128 个连接，另为公共准备与诊断连接预留 128；故障 PG 因串行使用，容量为 128。此容量覆盖组件 fixture 中的多个产品连接池，记录于 `postgres-start.maxConnections`；不是另一个并发开关，也不按该数量建库。

构建、发现和执行复用同一二进制与 Cargo 环境。每个发现的 ignored 业务测试必须有唯一模块归属；辅助子进程入口必须在同一模块描述中声明调用 owner，每个声明恰好发现一个入口；身份准备使用唯一 fixture target。未知 ignored helper 不再按命名空间豁免，函数名仍全部来自发现。空发现、重复归属、错误 CASE、缺依赖、二进制或运行中源码变化都失败。nextest JUnit 必须证明实际运行了唯一精确测试、无忽略/重试/失败；每个 Rust/Python 场景执行预算为 600 秒，Rust 的 nextest 与外层进程截止共同保证有界终止。Python 场景通过受控子进程执行并保留 test.log 完成标记；超时、取消及遗留 Compose 环境均由本轮统一清理。LIST 只构建实际发现所需目标，不额外构建身份辅助目标、产品 CLI 或运行期 examples，也不要求 Docker 等运行依赖。

`artifacts/local-t2/<runId>/` 保存 discovery、逐模块/逐调用结果，以及准备/执行/清理耗时。case 结果包含实际 database、tenant、PG、调用 ID 与单调时钟区间；`resources.json` 的 `counts` 和 `operations` 分别记录服务、克隆、身份账户/会话与故障恢复的数量和耗时。共享准备单独记录，不把它重复计入每条 case。`run.json` 分别记录 discovery/runtime 构建耗时及合计、JOBS、首次进入执行的延迟、运行墙钟时间、case 时间总和与受管子进程数量；后者不包含 Rust 子进程自行创建的后代。逐 case 的 queueSeconds 与准备／测试／清理区间区分排队和执行。PostgreSQL 的实际会话计数在删库／环境清理前采样，含工具自身观察连接；采样失败单列，不以估算补齐。环境 owner 还记录实际 container/port 查询次数。顶层 result 记录 Git revision 与工作区来源摘要，并区分执行与 skipped；正式执行开始前撤销旧 result，LIST 开始前只撤销旧 list，避免硬中断后误读上轮成功；另一模式证据保留，ci-plan 不覆盖正式证据。比较资源消耗应同时查看选择集合、PG/Identity/SCEP 等实际准备次数、并发时间区间和耗时；文件拆分不代表 Rust crate 编译量同比下降。

历史证据最多保留本入口最近 5 轮已确认归属的 runId 目录，保留当前运行及正式 result/LIST 引用的记录。LIST 不删除当前正式结果所指证据；空选择不创建运行目录。未知目录和符号链接不在清理范围。失败 case 的 `log` 指向实际输出，`failureLog` 指向异常栈；控制台同时打印两个路径。`fixtureLog` 保存该场景准备/清理命令失败时捕获的 stdout/stderr，并标明阶段；共享准备/清理失败关联 run 级 fixtureLog。命令参数不进入异常日志，包含已登记私有输入或敏感环境值的输出保守记为 `diagnostic-withheld`。

### 选择失败与结果

选择器成功返回 `status=selected`、独立 Cargo/T2 模式和唯一执行集合；原因记录包含输入与业务／工具／代表／显式全量归属。失败返回 `status=failed` 与错误类别、阶段、相关输入，并非零退出，正式 CI/T2 在准备依赖与执行前终止，撤销本入口旧通过结果。内部结果格式整体迁移，不接受旧 full 布尔格式。

`ci-plan` 只预览。`make ci` 执行选中工具测试并推荐 T2；独立 `make t2` 的 `toolVerification` 如实记录工具测试未运行，空模块结果为 skipped。`MODULE=all`、指定模块及 `ci-full` 不需要 affected 基线；`CI_FULL=1` 单独使用时仍只扩大快速检查。

## S3 内容适配验证

`make t2 MODULE=content.s3` 执行独立适配的真实 provider 测试；无需 PostgreSQL、Identity 或产品 App。唯一 fixture 由 T2 runner 管理，使用[固定 RustFS artifact](../../fixtures/s3-provider.lock.json)、私有 CA、版本化 bucket 和限定 prefix 的工作负载凭据。两个客户端直接消费正式 Store；创建、写入、分片及完成的响应丢失由 TLS 代理在读取 provider 成功响应后注入，不以 mock 的成功替代实际写入。原始秘密、管理 client 与代理只用于 fixture。

执行结果进入已有 local-t2 artifact；缺 Docker、TLS 工具或零测试发现必须失败。环境按 worktree 隔离，case 使用各自 prefix；结束后验证归属并删除本轮容器，下一轮可恢复清理遗留的同属容器。#2664 消费同一 fixture，不另建 S3 环境。

本项只验证锁定 RustFS 版本的对象/分片/错误恢复语义，不宣称所有 S3 provider、AWS IAM/KMS、生产部署、容量或性能已经验收。实际结果及未覆盖范围保留在 PR，不由文档宣布通过。


完整产品宿主同时持有业务租户和管理租户的投影，同一物理数据库只能有一个完整宿主。
其借用按数据库独占；配置变化必须先确认旧进程终止，再替换该槽位。能力用例不借用完整宿主时仍可并发。
`REUSE_PLAN` 的并发证明选择实际领域能力用例；完整产品宿主专项使用自己的环境。
宿主退出仅终止依赖它的当前执行、阻断该环境后续借用；用户中断才取消整次运行。
结果中的 `phase` 区分准备、执行和清理，`blocked` 引用原准备失败，`cancelled` 表示未完成的取消；
清理失败独立记录，不覆盖原始业务失败，任何选中用例非通过都会使本次验证失败。

普通业务审计断言读取 `rss_audit.records` 的已提交最终事实，与业务操作回执一起证明原子性及回放；不再驱动审计后台投影。
