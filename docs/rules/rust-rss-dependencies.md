# Rust 与 RSS 消费规则

自有服务端和 Agent 使用 Rust，分别维护独立 workspace、Cargo.lock、工具链与 CI。只依赖已接纳的 RSS 公共 API，不链接 RSS 内部源码路径，不加入 RSS workspace，不复制通用持久化机制。

## 依赖身份

#2346 已决定：RSS主仓公共包使用Azure Git，所有直接RSS主仓依赖固定同一完整
`git + rev`，精确值由 Cargo.toml 持有，完整上游依赖由 Cargo.lock 持有。
更新上游必须显式修改 pin、重新锁定并运行本地 CI；不得浮动跟踪 develop。
不保留 path patch、candidate 解包或 registry 备用构建路径；源码不可取得时明确失败。

Git checkout 内上游自身的 workspace/path 关系由 Cargo 解析为同一 Git source identity，
不允许产品直接引用父仓或机器目录。metadata 必须验证所有RSS主仓包属于同一固定Git commit。
本仓 `rss-mdm-*` 成员使用根 manifest 声明的 workspace 内部 path，CI 校验精确成员身份和位置；
这不允许引用仓外 RSS checkout，也不改变上游 Git pin 规则。
只读凭据由系统 Git credential helper 提供，不写入 manifest、lock 或日志。
这是 Git revision 独立消费，不是 `.crate` 摘要、candidate 或 registry 发布证明。
以后切换发布来源必须另行明确变更，不把本次 Git 证据混称为制品发布证据。

## 独立构建与兼容

在 RSS Cargo workspace 外，以独立 workspace、Cargo 配置与 target 从干净环境执行 locked 构建；核对 metadata/tree 的普通依赖图、RSS release surface 闭包、默认及实际 features。产品可以按现有布局嵌套在 RSS 文件目录下，但不能依赖父目录 .cargo 配置或其他 workspace member 合并 features。独立消费验收使用隔离 checkout，或等价地验证实际配置来源、metadata 和 feature 闭包；设置 CARGO_HOME 本身不代表已经排除祖先 .cargo 配置。

产品 CI 必须验证可重复获取依赖、fmt/check/clippy、受影响 T1/T2 与迁移接缝。真实 PostgreSQL 验证不能因缺服务而跳过后仍报告通过。工具链由 rust-toolchain.toml 锁定，完整入口为本地 `make ci`；本期不建立远端 CI。

升级 RSS 时同时核对公共 API、features、schema、错误/取消/提交不确定语义、资源关闭与产品行为。发现消费缺口回对应 RSS crate 修复；产品只保留业务 adapter，不建立临时修正版。

## 产品内部逐 crate 独立消费

本批能力名称与依赖禁边由 [ADR](../architecture/adr/202609072231-001-rust-rss-product-foundation.md#独立后端能力契约n01--2379) 唯一持有。
以下是明确消费者验收任务可显式运行的逐包方法；不属于任何本地 CI 入口。N01 只冻结方法，不新增 gate，也不声明逐包验证已经通过。

每个待验核心或 adapter 从已提交源码的固定 Git SHA 获取，由 RSS 与 rss-mdm workspace 外的最小 consumer
只直接依赖一个产品 package；此外可直接依赖该产品公共签名所需的 canonical RSS 值类型 owner。
当前 Scope、Policy、Software Release consumer 的精确直接依赖集合为该产品包、`rss-contract`、`rss-request-context`，
两个 canonical owner 的 features 均关闭；由 `hack/core_consumer.py` 校验精确集合、来源、features 及从产品包自身出发的依赖闭包，
不得通过 consumer 的直接依赖补齐产品包缺失的声明。
使用独立 workspace、Cargo.lock、Cargo 配置及 target，不通过父仓 path/patch、其他成员或隐式 feature 合并补齐依赖。
准备独立 lock 后执行 `cargo check --locked`、`cargo test --locked`，consumer 的测试通过公共 API 断言实际结果；
同时保存 `cargo metadata --locked --format-version 1` 和 `cargo tree --locked -e features`，分别检查默认及实际选择的 feature 组合。
核验祖先 Cargo 配置、package source identity 与依赖闭包，不能只设置 CARGO_HOME 就宣称隔离。

七项核心的闭包不得出现其他 MDM 核心、PG adapter、应用/Agent 或设备通道；纯决策核心不得带 HTTP/PG，平台源可带自身必要协议/Git 依赖。
PG adapter 可依赖对应核心及必要 RSS/PG，但不得夹带无关业务；真实 PG 验证 tenant/最低运行角色、并发、原子事件、回滚与 commit unknown 恢复。
WinGet 使用真实 HTTP、Brew 使用受控 Git，N11/N12 按路线承担实际组合 T2；核心 fixtures 不代替真实接缝，整仓编译不代替逐包消费，T1/T2 不代替 T3。

证明记录产品源码 SHA、RSS revision、consumer lock 摘要、实际 features/命令/结果与未覆盖项；Git 消费不称为 registry 发布。
consumer 行为用例及必要脚本随各实现 owner 入库，临时 workspace 可再生，不持有唯一测试源码；公共 Cargo/lock/CI 调整由单一集成人串行合并。

## 终端约束

Agent 仅消费确有需求且支持目标平台的公共核心/值类型，不带服务端 PostgreSQL、AMQP 或运行角色依赖。共享 wire 协议由产品协议包唯一维护；schema 版本、能力协商、未知字段、状态兼容和可升级窗口独立于 RSS crate 版本验证。

## Identity 消费（#2437）

独立 Identity 仓的四个公开包 core/postgres/http-axum/oidc 使用固定 Git URL + 同一完整 SHA，精确来源由 manifest/lock 持有。MDM 直接嵌入公开组件，拥有宿主装配与产品权限，不依赖参考应用或复制账户/认证机制。普通及测试依赖图分别检查 RSS 和 Identity 唯一来源/revision，禁止跨仓 path/patch。

OIDC 仅使用 RSA 公钥验证。新路径为 MDM app → rss-identity-oidc → openidconnect 4.0.1 → rsa 0.9.10；#2365 的旧路径豁免不继承，交付需基于最终 lock 和实际普通/测试闭包取得该路径的明确风险接受。修复版本可用时升级退出。测试 loopback 能力仅在显式 integration 测试构建中调用，生产装配固定使用 HttpOidc::new。

## MDM 后端支持包依赖

按[产品范围](project-scope.md#mdm-专属后端存储共享2430--2431)，三个 PG adapter
可依赖产品内部 `rss-mdm-backend-postgres-support`。支持包必须与 adapter 来自同一产品 SHA，
不依赖任何 MDM 核心/adapter/app/identity，无 feature 开关。它仅作为 adapter 传递依赖进入
独立 consumer；不扩大 Group 或七个核心的允许闭包，不调整 RSS 固定 pin。
