# Agent 协议

`rss-mdm-agent-wire` 是独立可消费的纯协议 crate，版本 `1.0.0`，最低 Rust `1.96.0`。`enroll` 持有注册生命周期 DTO；`runtime` 持有运行消息、采集定义与值、任务 DTO、静态约束、规范签名字节及内容摘要。当前 HTTP API、wireVersion、capability 和三类任务签名域保持 V1；注册族只维护当前 CSR 必填请求与完整签名配置文件，旧普通请求期限字段及 AuthorizationRequest shape 已退出。运行族 JSON 编码与摘要不变。

采集 DTO 由本包拥有，服务端在 Agent ingress 转成 Inventory 值。执行资格、当前凭据可用性和软件结果判定由 software-service 持有，上下文 revision 的更新规则由 agent-channel 持有。协议包不依赖 RSS、Identity 或 MDM 业务 crate，不执行设备操作、网络请求或运行时 schema 验证。CI 校验正常、build、可选及平台条件生产依赖；开发测试中的签名验证不进入交付闭包。

## 固定版本消费

本包按 RSS 的私有 Git 方式交付，保持 `publish = false`；Git 源码消费不称为 Cargo registry 发布。消费方在 manifest 中固定仓库 URL 与完整 40 位 `rev`，由系统 Git credential helper 或受保护的构建 secret 提供私库读取凭据。最终可消费 rev 与两族 schema 指纹由 #2686 的 PR 交接记录给出，独立 Agent #2685 在自己的仓库固定该 rev。

Cargo 下载 rss-mdm 仓库源码后，仅构建选中的协议 crate 及其公共基础库。消费方不得用相邻 checkout 的 path、浮动 branch/tag、来源 fallback 或后端 crate 代替此依赖。

不保留旧 Rust 方法、模块别名或版本解码。客户端自己持有受信密钥、设备坐标、可信时钟、签名验证与本机执行条件；`TaskPayload::signing_bytes` 只提供当前签名域的规范字节，不授予执行权限。服务端通过自己的审批与签名边界授权 Offer/Start。

## Schema 与固定向量

Rust DTO 及其静态约束注解是唯一结构来源。`examples/protocol_schema.rs` 生成两族当前 schema；`hack/agent_wire_artifact.py --write` 更新已有 schema 文件及指纹，不带参数核查清单、Rust 派生内容与指纹是否一致。修改手写 artifact 或只重算指纹不能通过核查。

`tests/fixtures/v1-vectors.json` 的规范 JSON、三类签名、采集指纹和报告/软件摘要来自未修改的 develop 基线，来源 SHA 记录在 fixture 中。它们验证本次 Rust API 重构保留当前 HTTP/JSON 编码，不构成旧 API 兼容承诺。

详见 [Agent 接入指南](../../docs/guides/agent-integration.md)。
