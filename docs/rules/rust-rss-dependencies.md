# Rust 与 RSS 消费规则

自有服务端和 Agent 使用 Rust，分别维护独立 workspace、Cargo.lock、工具链与 CI。只依赖已接纳的 RSS 公共 API，不链接 RSS 内部源码路径，不加入 RSS workspace，不复制通用持久化机制。

## 依赖身份

#2346 已决定：当前服务端仅使用 Azure RSS Git 公共包，所有直接 RSS 依赖固定同一完整
`git + rev`，精确值由 Cargo.toml 持有，完整上游依赖由 Cargo.lock 持有。
更新上游必须显式修改 pin、重新锁定并运行本地 CI；不得浮动跟踪 develop。
不保留 path patch、candidate 解包或 registry 备用构建路径；源码不可取得时明确失败。

Git checkout 内上游自身的 workspace/path 关系由 Cargo 解析为同一 Git source identity，
不允许产品直接引用父仓或机器目录。metadata 必须验证所有 RSS 包属于同一固定 Git commit。
只读凭据由系统 Git credential helper 提供，不写入 manifest、lock 或日志。
这是 Git revision 独立消费，不是 `.crate` 摘要、candidate 或 registry 发布证明。
以后切换发布来源必须另行明确变更，不把本次 Git 证据混称为制品发布证据。

## 独立构建与兼容

在 RSS Cargo workspace 外，以独立 workspace、Cargo 配置与 target 从干净环境执行 locked 构建；核对 metadata/tree 的普通依赖图、RSS release surface 闭包、默认及实际 features。产品可以按现有布局嵌套在 RSS 文件目录下，但不能依赖父目录 .cargo 配置或其他 workspace member 合并 features。独立消费验收使用隔离 checkout，或等价地验证实际配置来源、metadata 和 feature 闭包；设置 CARGO_HOME 本身不代表已经排除祖先 .cargo 配置。

产品 CI 必须验证可重复获取依赖、fmt/check/clippy、受影响 T1/T2 与迁移接缝。真实 PostgreSQL 验证不能因缺服务而跳过后仍报告通过。工具链由 rust-toolchain.toml 锁定，完整入口为本地 `make ci`；本期不建立远端 CI。

升级 RSS 时同时核对公共 API、features、schema、错误/取消/提交不确定语义、资源关闭与产品行为。发现消费缺口回对应 RSS crate 修复；产品只保留业务 adapter，不建立临时修正版。

## 终端约束

Agent 仅消费确有需求且支持目标平台的公共核心/值类型，不带服务端 PostgreSQL、AMQP 或运行角色依赖。共享 wire 协议由产品协议包唯一维护；schema 版本、能力协商、未知字段、状态兼容和可升级窗口独立于 RSS crate 版本验证。
