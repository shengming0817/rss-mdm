# Product telemetry

本 crate 拥有可信批次接收、设备与字段查询授权、配置交付及维护协调。字段定义与保留策略由 Inventory 持有；采集模板和 Profile 由 Resource 持有；分配、Scope 和发布权限由 Policy/Flow 持有。

接收记录只保存幂等身份、摘要、配置坐标和处理状态，待交付内容仅由 RSS Outbox 持有。事务内的注册、来源、配置绑定与额度检查先于原子接收。已经接受的批次按封存事实结清；后续撤权停止新接收，不改写已接受事实。未知结果使用原身份恢复。

历史查询每页重新授权，当前资产经既有 Observation/Inventory 接缝处理。持久接收、目的端准入、当前投影和窗口汇总分别表达。保留调度只记录精确序列坐标、固定维护身份与最新进度；裁剪、删除恢复和流生命周期算法由 RSS adapter 完成。

App 负责显式存储配置、安装准入、worker 生命周期和有界关闭。维护与备份操作见 [运维指南](../../docs/deployment/operations.md)，安装入口见 [安装指南](../../docs/deployment/installation.md)。
