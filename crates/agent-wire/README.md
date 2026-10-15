# Agent 协议

`rss-mdm-agent-wire` 是独立可消费的纯协议 crate，版本 `1.0.0`，最低 Rust `1.96.0`。`enroll` 持有注册生命周期 DTO；`runtime` 持有运行消息、采集定义与值、任务 DTO、静态约束、规范签名字节及内容摘要；`pki` 持有共享设备信任与安装确认 DTO、静态约束及规范安装摘要。当前 HTTP API、消息 wireVersion、capability 与 PKI 格式保持 V1；Collection 任务格式及签名域为 V2，其它任务签名域保持 V1；注册族只维护当前 CSR 必填请求与完整签名配置文件，旧普通请求期限字段及 AuthorizationRequest shape 已退出。V1 标识不代表跨 revision 的结构兼容；采集 scope 与 claim environment 是本次必填契约，相关采集指纹与报告摘要随之改变。PKI 的编码与安装摘要不受本次变更影响。

采集 DTO 由本包拥有，服务端在 Agent ingress 转成 Inventory 值。执行资格、当前凭据可用性和软件结果判定由 software-service 持有，上下文 revision 的更新规则由 agent-channel 持有。协议包不依赖 RSS、Identity 或 MDM 业务 crate，不执行设备操作、网络请求或运行时 schema 验证。CI 校验正常、build、可选及平台条件生产依赖；开发测试中的签名验证不进入交付闭包。

## 固定版本消费

本包按 RSS 的私有 Git 方式交付，保持 `publish = false`；Git 源码消费不称为 Cargo registry 发布。消费方在 manifest 中固定仓库 URL 与完整 40 位 `rev`，由系统 Git credential helper 或受保护的构建 secret 提供私库读取凭据。包含 PKI 制品的最终可消费 rev 与三族 schema 指纹由 #2688 合入后的交付记录给出；独立 Agent #2685 在自己的仓库固定该 rev，PR 交接或本地生成不代表固定候选已交付。

Cargo 下载 rss-mdm 仓库源码后，仅构建选中的协议 crate 及其公共基础库。消费方不得用相邻 checkout 的 path、浮动 branch/tag、来源 fallback 或后端 crate 代替此依赖。

不保留旧 Rust 方法、模块别名或版本解码。客户端自己持有受信密钥、设备坐标、可信时钟、签名验证与本机执行条件；`TaskPayload::signing_bytes` 只提供当前签名域的规范字节，不授予执行权限。服务端通过自己的审批与签名边界授权 Offer/Start。

## Schema 与固定向量

Rust DTO 及其静态约束是唯一结构来源。`examples/protocol_schema.rs` 生成 enroll/runtime/pki 三族当前 schema；`hack/agent_wire_artifact.py --write` 物化清单声明的 schema 文件并更新指纹，不带参数核查清单、Rust 派生内容与指纹是否一致。未登记文件、修改手写 artifact 或只重算指纹不能通过核查。

PKI 只导出两个 HTTP 根 schema：Trust 与 Acknowledgement，其引用的 Issuer/Purpose/Mode 由同一 Rust 声明派生。`Trust::validate` 与 `Acknowledgement::validate` 供直接构造 DTO 的消费者检查静态约束，反序列化使用相同判定；规范 UUID 文本检查在解码阶段完成。共享 Purpose 支持 Windows/Apple/Agent，Agent 消费方仍须显式检查 `purpose=agent`。证书与 CRL 验签、按 issuer digest 去重、身份绑定、防回滚及安装准入由产品消费者持有。安装摘要保留 issuer 顺序，排除 `crl` 与 `root_crl` 字节；schema 指纹与安装摘要分别标识制品和安装绑定。

`tests/fixtures/v1-vectors.json` 验证当前规范 JSON、任务签名、采集指纹和报告/软件摘要；#2719 已同步显式采集 scope 及其摘要。`baselineRev` 记录向量的初始来源，不表示此后的契约修改仍与该基线相同。`pki-v1-vectors.json` 保留其来源 revision 的 PKI JSON 与安装摘要。本仓向量验证当前契约，不构成旧 API 兼容承诺。

详见 [Agent 接入指南](../../docs/guides/agent-integration.md)。

采集定义必须显式携带 scope，当前只允许 device；其它范围不会降级为设备值。TaskClaimRequest 必须携带 environment（edition 可为 null、tools 为版本字典），OS/build 继续从 executionContext.osVersion 取得。旧缺失结构拒绝解码。需由独立 Agent 仓固定本次交付 rev/schema 指纹后实现，服务端测试不代表设备实测完成。

## 原生采集契约（#2739）

当前 TaskPayload 统一为显式 `{kind,task}`，类型为 script/software/enrollment/collection；旧无类型包络拒绝。claim environment 必须携带 nativeEngines，空对象表示不支持，不从 tools 或脚本 profile 推断原生能力。Collection 使用同一 plan/result 执行 Windows 与 macOS 设备级采集；用户应用与 Brew 范围接入同一采集链路，见 [资产指南](../../docs/guides/assets.md)。

`NativeCollectionPlan` 持有有界查询与引擎版本，输出结构由声明派生；Resource 持有资产映射。CPU 汇总须完整枚举处理器，型号不一致时省略 model，核心数不得只取第一颗；电池 charge_percent 为可用能量/完整充电能量的加权百分比，无法可靠计算则报告 Missing/Invalid。软件清单包括设备及所有现有用户的注册表安装记录与 MSIX 安装实例，实例 ID 须保留来源及用户坐标；预期用户集合在采集前后稳定且每个用户完整才可发布设备清单。未知 origin 或真实终端执行边界由后继 Agent 实现明确验证，本仓合成样本不代表实机完成。

Collection 使用独立签名域，Offer 与 Start 均签入 plan、预算、范围及完整任务坐标。结果逐 query 携带身份、时间、闭合状态、枚举结束和覆盖证据；共享 OutputChunk/OutputManifest 仅证明完整传输。原生结果没有 exitCode，查询失败不影响其他完整 query。大整数为带类型声明的规范十进制文本，禁止浮点降精度。

`tests/fixtures/native-v2-vectors.json` 包含 plan/result 指纹及 Collection Offer/Start 签名，`examples/native_collection_vectors.rs` 为可重复生成入口。schema 仍由当前 Rust DTO 统一派生。固定消费使用合入后的完整 Git rev，并核对当前 schema 指纹；不支持旧请求、旧签名形状或持久任务格式的兼容读取，不得清空 journal 或重新注册来跳过未决任务。

服务端保留完整 query 原始证据，范围可能超出映射字段（含未映射 query/property）。因此原生采集的预览、发布/执行和运行详情统一要求现有 InventorySensitiveRead 权限；InventoryCollect、资源/设备范围及 InventoryRead 仍各自校验。字段投影后的读取继续沿用字段敏感配置。正常执行结束并提交合法结果包时任务为 Succeeded，包括 query 全部 Denied/Timeout 的情况；采集失败/部分质量由 CollectionProgress 与 CollectionRun 独立表达。

### macOS 原生采集（#2737）

`macos.agent.*` 提供设备级硬件与 PKG receipts Resource 蓝图，支持 x86_64/aarch64。
硬件声明覆盖 identity、OS、CPU、memory、firmware、disks、APFS containers、volumes、network、battery。
APFS container 容量只计一次；volumes 蓝图保留 container 查询原始证据和卷关联，不把共享容量相加。
PKG receipts 写入 `device.software.receipts`，收据不证明应用当前存在；不得混入 installations。

Applications 的三个批准根与 Brew prefix/tap/formula/cask 已有闭合声明及结果类型。
Resource 可发布这些声明；服务端从同一 signed execution binding 冻结逐字段 scope，
按实际 UID、批准根或 prefix/tap/package 分开投影，完整空列表只替换该字段范围。
批准根、扫描参数和执行 UID 是采集材料，不自行授予 Inventory 范围权威。

Collection `wireVersion=2`、签名域 `rss-mdm-agent-collection-task-v2-ed25519` 强制携带
`execution`，绑定 System/LoggedInUser、context revision 与设备或登录会话。
Brew 和 UserApplications 只允许当前 helper 绑定的规范非零 UID；禁止 root、离线切换用户、
任意程序、脚本、环境覆盖或提权参数。消费方在 Offer/Start 验签后用
`NativeExecutionBinding::matches_context` 复核本机身份与会话；服务端 Start 同样重建并比较已签 Offer。
Brew 引擎 v1 使用安装记录 JSON v2；前缀是数据定位，不是可信可执行文件路径，
Agent 必须自行验证可信工具和批准数据根，缺工具、无权限、超时、截断分别报告现有闭合状态。

Mac 软件行的 origin 分别为 `application`、`pkg_receipt`、`homebrew`；Brew 行必须匹配声明的
prefix、tap 与 package_kind，用户 UID 必须非零。签名状态为 signed/unsigned/invalid/unknown。
完整空收据列表可发布；失败或截断保留旧值。所有原始证据，包括失败和未映射内容，仍要求
InventoryRead 与 InventorySensitiveRead。设备执行与真机支持矩阵由独立 Agent #2723 验证。

升级前停止签发旧 Collection 任务并等待其终态，保留审计与 journal；再协调切换服务端与固定 rev
的 Agent。旧 Collection v1 不解码、不执行，不清空 journal 或重新注册绕过未决任务。
固定候选完整 rev 和 schema 指纹记录在 #2737 的 PR 交接制品；#2723 可以独立消费该候选，
不等待 #2726 的范围投影集成。
