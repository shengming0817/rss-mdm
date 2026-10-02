# 架构

- [架构决策](adr/README.md)
- [资产变化与持久计划](asset-automation.md)
- [企业任务](enterprise-tasks.md)
- [Apple 原生管理](apple-management.md)

## 应用边界

| Cargo owner | 职责 |
|---|---|
| `authorization-service` | 当前管理主体、授权规则、授权证明及初始化 |
| `registration-service` | 注册世代、来源授权、凭据和设备生命周期 |
| `inventory-service` | 采集质量与持久接收、资产、分组及合规 |
| `flow-service` | 目标与 Scope/Policy 协调、任务组合和资源目录；Group/Compliance 管理入口直达 Inventory |
| `execution-service` | 冻结执行输入、命令、Run、Attempt、一次性远程操作、执行存储与交付恢复；独立 Queries 提供类型化读事实 |
| `content-service` | 内容授权、上传/镜像/回执用例、不可变文件与回收 |
| `management-http` | 浏览器管理 HTTP、会话与错误投影 |
| `agent-channel` | Agent 注册、报告、任务和内容协议 |
| `windows-channel` / `apple-channel` | 各平台注册、管理协议及持久协议关联状态 |
| `certificate` | 有界证书解析、密钥、签名与 TLS 对端证明 |
| `apple-mdm` / `windows-mdm` | 平台报文和 Profile 编解码 |
| `app` | 配置与文件加载、实例构造、跨能力接缝、路由合并、TLS 监听、readiness、生命周期与安装顺序 |

应用服务不依赖 Axum 或入口通道。各入口返回完成状态绑定的路由，并负责自己的请求预算、审计结算和协议错误；App 不维护业务路由前缀判断。证书能力不读取宿主配置文件，也不持有注册数据库或外部 CA 生命周期。

跨能力写入借用调用方的 PostgreSQL connection / transaction。发起业务的 owner 负责提交、回执与审计，参与方只修改自己持有的状态；注册及通道绑定、退休及采集终止仍在同一事务中完成。命令提交归 Execution，Windows / Apple 协议状态由通道参与写入。后台继续消费既有 RSS 持久恢复机制。

安装单元由各能力导出，App 只决定顺序。产品 schema 是当前完整定义；仅接受空库或完全一致的安装记录，不保留历史升级链、旧模块转发或双写路径。现有 App 集成测试继续验证实际装配，测试载体不构成生产 facade。

共享连接的准入由各能力 `access-contract.json` 声明自身表、列权限、函数和策略；App 只组合合同，Postgres support 检查合同并集及额外权限，Apple 的协议存储结构由 Apple 自检。入口只公开装配与 HTTP 类型，领域类型从原能力导入。入口错误保留服务来源，在响应边界映射；App 只拥有启动与生命周期错误。

Policy 管理直接消费 PolicyStore、资源版本读取和 Inputs，不持有整个 Planning。软件准备只借用目录与原生导出读取能力；已验证的导出描述不携带发布驱动、凭据或仓库写能力。App 单次装配独立 Inputs/Queries 与执行服务，再向各消费者借出对应对象。

各入口直接投影实际 owner 错误，Flow 不承接所有业务错误。Audit 的闭合诊断分类由 audit-integration 持有，事务结算仍由原发起方借用 RSS 完成。共享运行角色的完整越权检查属于 App 启动装配；Planning、Resource 和 Execution 分别核验自身事务所需合同，不扩张中央业务 owner 分类。
