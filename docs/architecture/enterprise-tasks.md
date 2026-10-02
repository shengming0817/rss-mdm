# Policy 与设备交付

Resource 持有不可变内容。Policy 持有组织持续分配，Execution 与 Configuration 是闭合类型；Operation、Run、Attempt 持有实际设备执行。管理员会话、岗位或权限变化不撤销已经发布的 Policy；当前管理员可显式停用或修改分配。

执行型 Policy 在 Agent 签入时按当前 Scope、触发、频率、窗口和历史原子受理。发布不展开全部设备 Run，没有 Policy×设备×周期任务矩阵。每次签入分页查询，持久游标循环访问后续策略。Offer、内容下载、Start permit 和事件回执复用原通道，签名绑定 tenant/device/registration/generation/task/attempt、内容摘要与预算。

频率区分每执行版本一次、每次入组一次、每次触发；直接设备分配只记录目标定义变化，不预生成设备任务。显式重执行是一条有期限的持久触发，仍由设备主动领取。定时触发在签入时计算，迟到按 Skip 的明确容忍秒数或 CoalesceOne 处理。窗口支持跨午夜，归属开始日；DST gap 跳过，fold 取较早时刻。已经开始而结果未知的脚本阻断同策略后续自动执行，不能用新版本绕过。

配置型 Policy 由成员、内容、注册与能力变化驱动。持久批次分页找出必要设备，比较期望配置和已知状态，再复用现有 MDM 队列。Windows 在管理会话交付；Apple 使用已有 APNs 通知及 MDM Profile 协议。同一效果由多个分配共享，不因一个分配退出而移除。冲突单独报告，Windows 防火墙退出不能声称回滚；Apple 仅移除本分配持有且受支持的 Profile。

## 持有与事务

`policy` / `policy-postgres` 持有 Policy 合同和配置存储，`flow-service` 的 `planning` 编排 Group、Scope 与 Policy。独立 `execution-service` 持有冻结执行输入、命令、Run、Attempt、远程操作、签名和交付恢复。Policy 发布只持有 Execution 的 `Inputs` 准备能力；Flow 不持有 `ExecutionService`、`Queries` 或私有 `ExecutionRead`。资源目录等非执行的 Flow 余项另行收敛。

Execution 不依赖 Flow。App 注入 Flow 实现的 `SourceAuthority`，在执行方原事务连接上读取类型化 Scope 准入、稳定快照、预览和分配设备页及 Policy 候选；不创建第二事务，也不传递完整 Flow 对象或授权黑盒。原生交付、回执及 Windows 缓存重放都重验当前来源、世代和授权。分配页锁定当前不可变 Scope 结果，在执行方合并有界来源页与自有执行记录。软件阶段计数保留单 SQL 的声明级快照，避免拆查询造成分母与 Run 事实不一致。

`Queries` 独立持有所需读依赖，不持有完整执行服务、outbox、reconcile 或签名私钥。目录、统计、复合游标、摘要、详情、能力及观察以类型化事实返回。摘要结果与完整详情分离，摘要移除输出和诊断流；详情与能力在事务内检查当前授权。目录先过滤可见设备，再统计和分页。HTTP 装配读写入口并持有路径：命令 v3、Policy Run v2、远程操作及其 Run v3。

数据库对象、序列化标签、请求身份和保护 AAD 保持原样，迁移按当前 owner 装配。Execution 持有 `mdm_commands` 以及配置核对、远程操作表；Flow 持有 Scope 和编排表。共用操作响应回执由 Audit Integration 单源持有，并借用调用方原事务；业务审计事实仍由实际业务 owner 生成。提交未知与回滚失败不会被转换为成功。


Scope 是目标计算的唯一 owner。成员三值结果、来源水位和定义版本共同决定准入；Unknown 排除依据不能放行。来源暂时计算中会阻止新执行，不能据此移除已有配置。已受理执行绑定注册世代，注册替换阻止旧任务继续启动。

配置持续分配和单次命令期限独立。临时缺少注册或能力时保留分配及诊断，相关事实到达后自动核对。脚本成功只表示退出结果；MDM 收到回执也不等于效果已经核实。采集输出仍通过 CollectionRun → Observation → Inventory，非法、部分、截断和迟到结果保留最后可信值。

Content 持有内容流及其锁、permit 与截止时间，Execution 持有任务签名和命令提交；Agent 通道持有 HTTP 报文转换。事务消息、后台 claim/lease 和协议状态机复用现有设施。Agent 与 MDM 共享关联身份和管理查询，各自保留状态机；不引入 Agent 推送、SSH 或远程终端。

## 来源

- jsonschema `c6ee21efc29083422e466aceb2a15bf1e50c83b3`，`crates/jsonschema/src/options.rs`。
- ring `2723abbca9e83347d82b056d5b239c6604f786df`，`src/signature.rs`。
- Jiff `4100a7c71125b9523029566d1d18f8b227ecd18c`，`crates/jiff/src/tz/ambiguous.rs`。
- osquery `1889d51f0d1680672016a801e9d65799eb5fc5dc`，`osquery/config/packs.cpp`、`specs/utility/osquery_info.table`。
