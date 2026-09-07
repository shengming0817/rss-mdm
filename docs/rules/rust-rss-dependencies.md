# Rust 与 RSS 消费规则

自有服务端和 Agent 使用 Rust，分别维护独立 workspace、Cargo.lock、工具链与 CI。只依赖已接纳的 RSS 公共 API，不链接 RSS 内部源码路径，不加入 RSS workspace，不复制通用持久化机制。

## 依赖身份

- 为实际需要的 capability 选择精确版本、RSS source commit、artifact SHA-256、来源、必要 features 和迁移版本；版本号相同不能代替字节身份。
- 优先使用经过确认的 registry artifact；研发阶段允许可校验、可重建的精确 candidate `.crate` 闭包，不以等待全体 GA 阻塞消费验证。
- candidate 仅作为显式研发输入，记录来源、打包证明和摘要；解包到隔离目录后可用临时 manifest/patch 完成消费证明，但路径只能指向这些 artifact，不能指向 RSS checkout。该证明不等于 registry 发布，也不自动批准生产发布。
- 产品常规构建在依赖落地 PR 明确采用的 registry/制品源下解析并锁定；不得将临时 path patch 或私有机器目录写成日常构建前提。若 artifact 缺失，阻塞对应消费验收并向 RSS 原 owner 补交付，不复制源码绕过。

Cargo 同时写 version 与 path 时，本地仍使用 path，不能以存在 version 字段声称已完成独立消费。具体语义见 [Cargo 依赖规范](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)。

## 独立构建与兼容

在 RSS Cargo workspace 外，以独立 workspace、Cargo 配置与 target 从干净环境执行 locked 构建；核对 metadata/tree 的普通依赖图、RSS release surface 闭包、默认及实际 features。产品可以按现有布局嵌套在 RSS 文件目录下，但不能依赖父目录 .cargo 配置或其他 workspace member 合并 features。独立消费验收使用隔离 checkout，或等价地验证实际配置来源、metadata 和 feature 闭包；设置 CARGO_HOME 本身不代表已经排除祖先 .cargo 配置。

产品 CI 必须验证可重复获取依赖、fmt/check/clippy、受影响 T1/T2 与迁移接缝。真实 PostgreSQL 验证不能因缺服务而跳过后仍报告通过。实际工具链和命令在 workspace 实施 PR 锁定，本文不伪称已经建立 CI。

升级 RSS 时同时核对公共 API、features、schema、错误/取消/提交不确定语义、资源关闭与产品行为。发现消费缺口回对应 RSS crate 修复；产品只保留业务 adapter，不建立临时修正版。

## 终端约束

Agent 仅消费确有需求且支持目标平台的公共核心/值类型，不带服务端 PostgreSQL、AMQP 或运行角色依赖。共享 wire 协议由产品协议包唯一维护；schema 版本、能力协商、未知字段、状态兼容和可升级窗口独立于 RSS crate 版本验证。
