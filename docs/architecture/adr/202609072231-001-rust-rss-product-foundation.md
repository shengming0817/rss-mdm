# 基于 RSS 的 Rust 产品重写

决定：产品与基础机制按权威边界分仓，自有实现采用 Rust。此决定替代按历史 Go 微服务复制工程；历史来源见 [基线](../../reference/202609072231-003-rss-current-baseline.md)。

## 仓库与依赖边界

RSS 提供已接纳的持久机制；MDM 定义身份、采集、资产、组、策略、软件与平台协议，并拥有装配、产品迁移及交付。Identity 持有账户与会话，MDM 持有业务授权。Agent 拥有设备侧采集、执行和升级，Web 拥有页面与 API 消费。稳定职责以 [范围规则](../../rules/project-scope.md) 为准。

共享 wire 由 MDM 协议包唯一维护，Agent 按明确版本消费；不传 Rust 内存对象，不引入服务端存储闭包。线上协议兼容不等于两端 Cargo 版本相同。通道中立身份先于平台适配，Agent-only 与 Apple 不依赖 Windows 注册完成。

## 独立后端能力契约（N01 / #2379）

Group、Scope、Policy、Resource、Software Release 各持单一决策职责，不互相泄漏业务类型；WinGet/Brew 只带必要源协议。组合根显式映射，纯核心不依赖 HTTP/PG/设备通道。PG adapter 只依赖对应核心与必要 RSS/PG，不读取其它 owner 的私表；公共类型与包身份以源码、manifest/rustdoc 为准。

静态组与动态成员同归 Group 持久 owner，动态重算不覆盖静态成员。Scope 定义/引用归应用，核心仅解释来源；跨 owner 引用新增、删除及计划保存由受控事务序列化，不能用先查后写绕过竞争。安全撤销不受业务引用阻止。

保存计划只是意图，执行进度与设备效果分别由实际执行 owner 提供。发布源元数据也不是终端安装。输入完整性、Unknown、提交未知和历史身份不能被简化为成功/失败二值。

## 持久化与取舍

事务消息、Projection、Command、Reconcile 复用 RSS 公共接缝，不新建通用 Outbox/UnitOfWork。宿主持有 runtime 及资源关闭；业务成功与审计同事务，外部调用的提交未知按稳定身份对账。

Reconcile 与 Device Command/Outbox 组合时，显式启用 reconcile-postgres 的 `transactional-messaging` feature，并使用 `messaging::protect/wake_with` 回调提供的消息 `PgTransaction`；默认 reconcile 事务是另一种类型。Outbox 必须属于精确同一个消息 `PgRuntime` 实例，不能仅凭连接同库认定可组合。消息 runtime 只结算自己的借用事务，Observation 与 Projection 各自拥有接收、投影事务；共享数据库不等于共享事务。产品 repository 通过公开借用连接接缝参加既有事务，组合根负责验证这些约束。

| 权威坐标 | 粒度与职责 |
| --- | --- |
| Device Command generation/epoch | tenant + device；替代设备计划，由产品统一推进，不能由各策略独立推进 |
| Reconcile claim epoch | tenant + reconciler + entity；调度租约，entity 到设备由产品映射 |
| Messaging execution fence | storage identity/lineage + tenant epoch；恢复和存储执行隔离 |
| Observation stream epoch/sequence | 授权来源、数据集与注册流；报告顺序和完整性 |
| Projection source lineage/generation | journal 身份与投影定义；重建和读模型切换 |

上述坐标相互关联但不能共用一个 epoch 字段。命令幂等 ID 在 tenant 内唯一；reconcile 的内部完成状态不代表设备已 Applied。Observation 的 durable receipt、Inventory 投影完成和设备收敛分别提供证据，不能互相替代。

组合根逐项声明 pool 的拥有者、借用者、worker 停止与 pool 关闭责任；`PgPool.clone` 不提供生命周期隔离。基线优先各 owner 独立 pool，事务内 bridge 使用借用连接与正确角色。Observation → Projection 的 SQL bridge 要求在同一数据库按正确 tenant 读取 journal；跨库交付需显式去重，不能沿用本地原子性假设。

三个后端 PG adapter 的重复机制收敛到产品内部 backend-postgres-support；它不依赖业务核心/应用、不成为新通用平台，Group 不为复用而被迫接入。此补充对应 #2430/#2431，依赖禁边由 [消费规则](../../rules/rust-rss-dependencies.md) 持有。

分层增加显式映射，但避免一套大 DTO/数据库成为所有能力的隐式契约。不创建空壳包、全局容器或兼容 facade。路线见 [工程路线](../../product/roadmap.md)，操作与恢复由 [指南](../../guides/README.md) 拥有。
