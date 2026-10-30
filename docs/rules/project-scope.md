# 产品能力与范围

rss-mdm 面向 Windows 与 macOS 的企业私有化终端管理。功能目标、排除项与待冻结参数以 [PRD](../product/rss-mdm-prd.md) 为准；目标范围不代表已实现或已批准发布。

工程方向遵循 [项目目标](../product/project-goals.md)：自有 Rust 服务端与 Agent 分别在 rss-mdm、rss-mdm-agent；首期不新增 RSS 通用 crate，不使用孵化仓或第三共享仓，现有前端先保留。

## 产品拥有

设备身份与注册生命周期、Windows/macOS 协议与认证、MDM/Agent 通道选择、策略和准入、软件源与应用模型、采集字段与资产解释、分组与合规、控制台，以及应用装配、业务表、生产迁移、部署运维与产品 T3。

## RSS 边界

RSS 提供其明确接纳的公共契约、事务消息、Saga、投影、状态收敛及相关基础能力。产品按实际可用的公共 API 消费，不把范围接纳当作已发布证明；不因产品需要就自动向 RSS 迁入协议、业务模型、装配或运维职责。新增通用机制须在 RSS 独立完成准入判断。

## 需求分级

- 一级：补齐身份、接口、状态、执行与安全等关键盲区。
- 二级：形成可运行、可核实、可恢复的产品闭环，权限、密钥与审计随能力交付。
- 三级：按明确需求独立确认的可选增强，不自动阻塞已冻结的一、二级交付。

每次设计核对设备、管理主体、租户与授权边界；不能隐含假设单租户，也不能由多身份源自动宣称已实现多租户隔离。具体承诺以发布范围为准。

## MDM 专属后端存储共享（#2430 / #2431）

`rss-mdm-backend-postgres-support` 是产品内部实现，仅供 Policy、Resource、Software Release
三个 PG adapter 直接消费。单源持有相同的文档/回执/不可变记录执行、权限及 catalog 检查机制，
借用既有 RSS 事务与 outbox；不新增通用 repository，不复制 RSS 引擎，不自建 runtime 或提交事务。
领域模型、请求和事件身份、业务 schema/迁移及准入策略仍归各 adapter；七个核心不依赖本包。
允许这种 MDM 专属实现共享，不将产品需要或代码同构视为 RSS 公共能力准入。
旧执行副本直接删除，不保留兼容转发层或双路径。公共产品行为与持久化格式不变。

## MDM 产品审计接入（#2498）

`rss-mdm-audit-integration` 是产品内唯一审计接缝，直接消费者限定为 App、device-service、pki-service、certificate-archive-service、recovery-credentials、timeline-service、software-service、authorization-service、registration-service、inventory-service、scope-service、resource-service、policy-service、execution-service、content-service，以及 webhook-service、mail-service、telemetry-service、management-http、agent-channel、windows-channel、apple-channel；实际依赖集合由 CI 校验。
不反向依赖 App、Identity 或任何 MDM 领域/应用包，纯领域核心不得依赖它。
活动事实共享 agent-wire 唯一持有的闭合协议枚举（#2937）；该纯协议依赖的生产闭包仍由 CI 独立校验，不引入业务实现或运行时。
产品事实映射、请求结算和取消诊断归此包；业务事件、主体真实性、资源授权和操作回执仍归各业务 owner。
最终 Audit 与业务状态在原 RSS 事务直接提交，组件 schema、追加和可选链完整性归 Audit/Ledger。
不维护审计 Outbox/Inbox 中转、复制回执或第二套事务恢复状态。业务回放使用原操作回执，不重复追加业务事实。

`collection_runs.delivery_pending` 是已提交报告成功消费后的派生确认，
`mdm_apple.devices.identity_health` 是从已存证书及当前时间计算的健康提示。
这两类内部标记更新不生成新的业务/审计事实；它们不改变注册世代、证书或采集结果。
其事务直接提交后结束，不生成业务审计事实。真实业务事实、操作回执与业务状态由同一个原事务提交。
Plain 没有全租户审计头锁；显式 Ledger 在业务锁之前取得链锁。业务并发不依赖审计串行化，
由自己的操作锁或唯一约束保护。消息机制保留给真实消息消费者。

审计组件的主体字段是中立数据，不充当身份认证证明。在线 principal 由 authorization owner 的
`AuthorizedPrincipal` 绑定并核对审计租户；初始化和软件恢复分别消费已验证的初始化用户及持久化
ActorId。结构守卫限制原始字段写入这些 owner。事实构造失败使用不含输入值的闭合类别；宿主区分
契约错误、完整性错误和中断，结算状态仍由原事务 owner 决定。宿主预算对象仅持有 timer、绝对
截止时间与取消 token；读历史借出 Audit Control，业务写入借出 SourceControl。重复借用不延长预算，
事务执行与结算归 RSS。审计必要性由产品 AuditIntent 声明，与事务结果独立。普通读取、轮询、常规遥测和安装包下载不写管理审计；普通拒绝使用有界日志和计数。关键变更保留原子业务事实，敏感读取、关键越权和多阶段最终结果在受保护响应交付前可靠提交。SensitiveAction 单源标识凭据披露、私密证书导出、审计检索、脚本内容及资产/遥测批量导出；业务动作名称仍归各 owner。

`mail-service` 仅持有 SMTP 材料、资格和固定测试投递，不拥有通知订阅产品。管理入口复用产品授权和 Audit，网络资格由显式一次性维护命令核验。
