# 架构

- [架构决策](adr/README.md)
- [资产变化与持久计划](asset-automation.md)
- [企业任务](enterprise-tasks.md)
- [Apple 原生管理](apple-management.md)

## 应用边界

| Cargo owner | 职责 |
|---|---|
| `authorization-service` | 当前管理主体、授权规则、授权证明及初始化 |
| `registration-service` | 注册世代、来源授权、凭据和设备生命周期；Entra 注册策略与 Windows 注册操作回执 |
| `inventory-service` | 采集质量与持久接收、资产、分组及合规 |
| `scope-service` | 目标定义、冻结成员计算、当前 Scope 结果与发布 |
| `policy-service` | Policy 管理、发布、重跑、分配核对、事件接受与成员决定、业务审计、事务结算及所属 worker |
| `resource-service` | 资源目录、不可变版本发布、启用和归档用例 |
| `flow-service` | 剩余设备来源变化扫描，调用 Execution 持有的推进算法 |
| `execution-service` | 冻结执行输入、命令、Run、Attempt、一次性远程操作、执行存储与交付恢复；独立 Queries 提供类型化读事实 |
| `content-service` | 内容授权、上传/镜像/回执用例、不可变文件与回收 |
| `management-http` | 浏览器管理 HTTP、会话与错误投影 |
| `agent-channel` | Agent 注册、报告、任务和内容协议；事件入口直接消费 Policy 批次服务 |
| `windows-channel` / `apple-channel` | 各平台注册、管理协议及持久协议关联状态 |
| `certificate` | 有界证书解析、密钥、签名、证书约束与 TLS 握手来源证明 |
| `device-trust` | 三平台设备信任、issuer 世代、撤销与证书验证组合；依赖 certificate |
| `apple-mdm` / `windows-mdm` | 平台报文和 Profile 编解码 |
| `app` | 配置与文件加载、实例构造、跨能力接缝、路由合并、TLS 监听、readiness、生命周期与安装顺序 |

应用服务不依赖 Axum 或入口通道。各入口返回完成状态绑定的路由，并负责自己的请求预算、审计结算和协议错误；App 不维护业务路由前缀判断。证书能力不读取宿主配置文件，也不持有注册数据库或外部 CA 生命周期。

跨能力写入借用调用方的 PostgreSQL connection / transaction。发起业务的 owner 负责提交、回执与审计，参与方只修改自己持有的状态；注册及通道绑定、退休及采集终止仍在同一事务中完成。命令提交归 Execution，Windows / Apple 协议状态由通道参与写入。后台继续消费既有 RSS 持久恢复机制。

Policy 普通持久工作使用 `mdm.policy`，事件使用 `mdm.policy-events`；Flow 来源扫描只消费 `mdm.assets/changes`。App 持有一个 2 连接 scheduler pool，将同一 PgStore 借给各业务 worker 并负责关闭。Policy 与来源扫描并发各为 1，事件并发为 2；各自通知、启动补扫和周期恢复独立。

安装单元由各能力导出，App 决定顺序并校验稳定安装身份。产品 schema 是当前完整定义，只支持全新安装和当前安装重放。可变租户登记由产品 App 持有；首次与后续租户共用事务登记入口，当前 epoch 仍由 RSS fencing 持有。测试载体不构成生产 facade。

共享连接的准入由各能力 `access-contract.json` 声明自身表、列权限、函数和策略；App 只组合合同，Postgres support 检查合同并集及额外权限，Apple 的协议存储结构由 Apple 自检。入口只公开装配与 HTTP 类型，领域类型从原能力导入。入口错误保留服务来源，在响应边界映射；App 只拥有启动与生命周期错误。

Policy 管理直接消费 PolicyStore、资源版本读取和 Inputs。软件准备只借用目录与原生导出读取能力；已验证的导出描述不携带发布驱动、凭据或仓库写能力。App 先装配 Policy 来源读取，再装配独立 Inputs/Queries 与执行服务，最后将同一个 Execution runtime 显式注入 Policy 事件服务及事件推进。

各入口直接投影实际 owner 错误，Flow 不承接所有业务错误。Audit 的闭合诊断分类由 audit-integration 持有，事务结算仍由原发起方借用 RSS 完成。共享运行角色的完整越权检查属于 App 启动装配；Policy、Scope、Resource 和 Execution 分别核验自身事务所需合同，不扩张中央业务 owner 分类。

Entra 注册策略的管理用例、模型、策略表和 Windows 注册操作回执由 registration-service 唯一持有。
management-http 与 windows-channel 直接消费该应用边界；Windows 通道持有 token、TOU、consent 和原生协议。
回执 API 借用原事务 connection，策略更新与原生 issuance 保留各自事务结算；HTTP 错误由管理入口投影。
当前安装定义按该归属重新组成，只支持空库安装与精确当前 manifest 重放，不提供旧安装兼容路径。
