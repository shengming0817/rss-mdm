# rss-mdm-software-service

产品内企业软件准入与外部 publication 协调。Resource 是唯一不可变定义权威，目录批准与外部三环发布保持独立。管理操作与内容协议见[资源与软件](../../docs/guides/resources-and-software.md)。

`catalog::Catalog` 借用宿主 `PgTransaction`，不提交或关闭宿主 runtime；状态、原操作回执、审计及 Outbox 由同一事务结算。`ContentPort` 在事务外验证并固定完整产物，`VerifiedContent` 必须持有这些文件直到批准事务结束。`resolve_admitted_in` 返回当前准入的精确变体及来源，`recheck_admitted_in` 拒绝用新批准替换已冻结批准。

`publication::PublicationService` 保留外部调用的持久意图、attempt、撤回和 Unknown 恢复。`AuditPort` 必须使用借入事务；`Credentials` 仅解析宿主批准的精确 tenant/source/reference。软件服务不读取宿主秘密文件，不反向依赖 App。

提取参照：Axum axum-v0.8.9 流式正文、zip-rs v8.6.0 受限读取；既有 WinGet/Brew 适配及事务算法仍由原 owner 持有。
