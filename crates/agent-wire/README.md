# Agent 协议

`rss-mdm-agent-wire` 是独立可消费的纯协议 crate，版本 `1.0.0`，最低 Rust `1.96.0`。`enroll` 持有注册生命周期 DTO；`runtime` 持有运行消息、采集定义与值、任务 DTO、静态约束、规范签名字节及内容摘要；`pki` 持有共享设备信任与安装确认 DTO、静态约束及规范安装摘要。当前 HTTP API、消息 wireVersion、capability 与 PKI 格式保持 V1；Collection 任务格式及全部任务签名域均为 V1；注册族只维护当前 CSR 必填请求与完整签名配置文件，旧普通请求期限字段及 AuthorizationRequest shape 已退出。V1 标识不代表跨 revision 的结构兼容；采集 scope 与 claim environment 是本次必填契约，相关采集指纹与报告摘要随之改变。PKI 与任务信任使用稳定 serviceId，注册文件嵌入签名连接配置；当前结构和摘要随本次更新。

采集 DTO 由本包拥有，服务端在 Agent ingress 转成 Inventory 值。执行资格、当前凭据可用性和软件结果判定由 software-service 持有，上下文 revision 的更新规则由 agent-channel 持有。协议包不依赖 RSS、Identity 或 MDM 业务 crate，不执行设备操作、网络请求或运行时 schema 验证。CI 校验正常、build、可选及平台条件生产依赖；开发测试中的签名验证不进入交付闭包。

## 固定版本消费

本包按 RSS 的私有 Git 方式交付，保持 `publish = false`；Git 源码消费不称为 Cargo registry 发布。消费方在 manifest 中固定仓库 URL 与完整 40 位 `rev`，由系统 Git credential helper 或受保护的构建 secret 提供私库读取凭据。包含 PKI 制品的最终可消费 rev 与五族 schema 指纹由 #2688 合入后的交付记录给出；独立 Agent #2685 在自己的仓库固定该 rev，PR 交接或本地生成不代表固定候选已交付。

Cargo 下载 rss-mdm 仓库源码后，仅构建选中的协议 crate 及其公共基础库。消费方不得用相邻 checkout 的 path、浮动 branch/tag、来源 fallback 或后端 crate 代替此依赖。

不保留旧 Rust 方法、模块别名或版本解码。客户端自己持有受信密钥、设备坐标、可信时钟、签名验证与本机执行条件；`TaskPayload::signing_bytes` 只提供当前签名域的规范字节，不授予执行权限。服务端通过自己的审批与签名边界授权 Offer/Start。

## Schema 与固定向量

Rust DTO 及其静态约束是唯一结构来源。`examples/protocol_schema.rs` 生成 enroll/runtime/task_trust/pki/connections 五族当前 schema；`hack/agent_wire_artifact.py --write` 物化清单声明的 schema 文件并更新指纹，不带参数核查清单、Rust 派生内容与指纹是否一致。未登记文件、修改手写 artifact 或只重算指纹不能通过核查。

PKI 只导出两个 HTTP 根 schema：Trust 与 Acknowledgement，其引用的 Issuer/Purpose/Mode 由同一 Rust 声明派生。`Trust::validate` 与 `Acknowledgement::validate` 供直接构造 DTO 的消费者检查静态约束，反序列化使用相同判定；规范 UUID 文本检查在解码阶段完成。共享 Purpose 支持 Windows/Apple/Agent，Agent 消费方仍须显式检查 `purpose=agent`。证书与 CRL 验签、按 issuer digest 去重、身份绑定、防回滚及安装准入由产品消费者持有。安装摘要保留 issuer 顺序，排除 `crl` 与 `root_crl` 字节；schema 指纹与安装摘要分别标识制品和安装绑定。

`tests/fixtures/v1-vectors.json` 验证当前规范 JSON、任务签名、采集指纹和报告/软件摘要；#2719 已同步显式采集 scope 及其摘要。`baselineRev` 记录向量的初始来源，不表示此后的契约修改仍与该基线相同。`pki-v1-vectors.json` 保留其来源 revision 的 PKI JSON 与安装摘要。本仓向量验证当前契约，不构成旧 API 兼容承诺。

详见 [Agent 接入指南](../../docs/guides/agent-integration.md)。

普通注册采集定义必须显式携带 scope，当前只允许 device；原生 Collection 任务按冻结 recipe 和签名执行主体确定字段范围，其它范围不会降级为设备值。TaskClaimRequest 必须携带 environment（edition 可为 null、tools 为版本字典），OS/build 继续从 executionContext.osVersion 取得。旧缺失结构拒绝解码。需由独立 Agent 仓固定本次交付 rev/schema 指纹后实现，服务端测试不代表设备实测完成。

## 原生采集契约（#2739）

当前 TaskPayload 统一为显式 `{kind,task}`，类型为 script/software/enrollment/collection；旧无类型包络拒绝。claim environment 必须携带 nativeEngines，空对象表示不支持，不从 tools 或脚本 profile 推断原生能力。Collection 使用同一 plan/result 执行 Windows 与 macOS 设备级采集；用户应用与 Brew 范围接入同一采集链路，见 [资产指南](../../docs/guides/assets.md)。

`NativeCollectionPlan` 持有有界查询与引擎版本，输出结构由声明派生；Resource 持有资产映射。CPU 汇总须完整枚举处理器，型号不一致时省略 model，核心数不得只取第一颗；电池 charge_percent 为可用能量/完整充电能量的加权百分比，无法可靠计算则报告 Missing/Invalid。软件清单包括设备及所有现有用户的注册表安装记录与 MSIX 安装实例，实例 ID 须保留来源及用户坐标；预期用户集合在采集前后稳定且每个用户完整才可发布设备清单。未知 origin 或真实终端执行边界由后继 Agent 实现明确验证，本仓合成样本不代表实机完成。

Collection 使用独立签名域，Offer 与 Start 均签入 plan、预算、范围及完整任务坐标。结果逐 query 携带身份、时间、闭合状态、枚举结束和覆盖证据；共享 OutputChunk/OutputManifest 仅证明完整传输。原生结果没有 exitCode，查询失败不影响其他完整 query。大整数为带类型声明的规范十进制文本，禁止浮点降精度。

`tests/fixtures/native-v1-vectors.json` 包含 plan/result 指纹及 Collection Offer/Start 签名，`examples/native_collection_vectors.rs` 为可重复生成入口。schema 仍由当前 Rust DTO 统一派生。固定消费使用合入后的完整 Git rev，并核对当前 schema 指纹；不支持旧请求、旧签名形状或持久任务格式的兼容读取，不得清空 journal 或重新注册来跳过未决任务。

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

Collection `wireVersion=1`、签名域 `rss-mdm-agent-collection-task-v1-ed25519` 强制携带
`execution`，绑定 System/LoggedInUser、context revision 与设备或登录会话。
Brew 和 UserApplications 只允许当前 helper 绑定的规范非零 UID；禁止 root、离线切换用户、
任意程序、脚本、环境覆盖或提权参数。消费方在 Offer/Start 验签后用
`NativeExecutionBinding::matches_context` 复核本机身份与会话；服务端 Start 同样重建并比较已签 Offer。
Brew 引擎仅接受 V1：只读批准 prefix 下 Cellar/Caskroom 的安装记录和可识别 JSON 元数据，
不启动 brew/Ruby/shell、不求值 formula/cask。版本与 tap 取自安装证据，不从当前目录或默认 tap 猜测。
数据可以由用户拥有，但必须作为不可信输入有界解析；不跟随逃出批准根的链接。
缺失、无权限、格式不支持、超时、截断或扫描期间变化分别保留失败证据，不能当完整空清单。
新固定候选只接纳匹配安装 manifest 的服务端与 Agent；旧实例继续按原版本结算任务并保留 journal，不通过旧引擎回退或清除状态切换。

Mac 软件行的 origin 分别为 `application`、`pkg_receipt`、`homebrew`；Brew 行必须匹配声明的
prefix、tap 与 package_kind，用户 UID 必须非零。签名状态为 signed/unsigned/invalid/unknown。
完整空收据列表可发布；失败或截断保留旧值。所有原始证据，包括失败和未映射内容，仍要求
InventoryRead 与 InventorySensitiveRead。设备执行与真机支持矩阵由独立 Agent #2723 验证。

本候选不提供旧实例原地升级；安装器及运行期只接纳精确安装 manifest。
旧数据库中的执行上下文、冻结 Resource、查询及规则不能因任务排空就切换为新结构。
旧实例应由原版本按原生命周期结算，保留注册、journal、审计与资产；不清库或重新注册绕过。
本次运行路径只接受当前 Collection V1 结构。
固定候选完整 rev 和 schema 指纹以当前契约 PR 的交接制品为准；独立 Agent 应固定同一候选，
不能继续沿用旧 Brew 命令契约的源码或签名向量。

### 安全、账户、证书与更新

`NativeQueryDefinition::System` 的封闭 `NativeSystemQuery` 持有两平台专用只读 recipe；
类型、输出列、引擎和版本以 [Rust 声明](src/native_collection/system.rs) 及派生 schema 为准。
已有 WMI/Registry 继续承载可完整表达的事实；DeviceGuard 保留配置/运行数组和 VBS 原值，
成员解释不使用位掩码或“数组非空”。专用 BitLocker recipe 只允许固定只读方法，不能提交方法名。

macOS 当前交互用户在现有 executionContext 中必须显式提供规范 GeneratedUID；Windows 为 null。
Collection V1 在原有 UID/SID、会话和 context revision 外签入稳定账户身份，Start 必须重新匹配。
新 macOS 用户字段的范围包含 UID/GeneratedUID；Apple MDM 用户 UUID 与此身份不同。
同一资源的 dataset 包含稳定账户身份，不包含会话、执行时间或扫描模式。

证书仅输出 SHA-256 指纹及批准元数据。每次只读一个设备或当前用户 store；不加载离线 hive、
解锁 keychain、提示用户授权或遍历历史用户。用户缺席、权限不足与 store 不可访问不是完整空列表。
所有新 recipe 的失败/部分结果也校验封闭输出；错误 owner 的结果拒绝接收，不进入资产事实。

更新查询默认 Local，Online 为单独标准包。Windows 使用现有 WUA 配置，必须关闭自动 WUA 升级，
不注册/更改更新服务、不下载、不安装、不重启。macOS 只执行版本可核实的只读查询。
每个更新结果都必须携带 `scan`，包括失败和空列表；本地缓存保留原扫描区间，未扫描不得编造时间。
源使用无凭据的标识，不上传更新源 URL 或凭据；行的 origin 与扫描源一致。
完整空结果需要真实完成证据；NotScanned、源不可用、失败、部分和截断保留旧事实。

指定安全应用只允许 Agent 自身或明确的签名应用身份，不接受命令、任意路径或全量 TCC 查询。
安装、签名、配置、运行和健康分别表达；没有厂商可验证的健康 API 时 health 为 unknown。
FileVault、硬件加密、Secure Token、Bootstrap Token 的本地状态不证明恢复材料或 Token 已由服务器托管。
固定候选的完整 Git revision 由交付评论提供；服务端受控样本不证明真实平台执行效果。

BitLocker conversion/lock 沿用既有 Inventory 闭合词汇，无法读取时省略该列并报告 Partial，
不新增同义字段或改写历史字段类型。完整列表要求每卷必要列齐全；未知保护状态仍用既有 unknown。
部分卷证据可留作诊断，但不能将不完整列表发布为当前完整卷清单。

包含 System recipe 的计划总输出上限为 1 MiB，只接受 inline CollectionResult。
原始 OutputChunk 和 ChunkedCollectionResult 在写入前拒绝；验证通过的大结果仍可由服务端沿现有存储分块保留。
Agent 达到预算须返回 Truncated 的有界结果，保留旧事实，不能偷偷切换到未校验分块。

`device.unmanage.v1` 提供固定的管理员授权退出任务。独立签名域
`rss-mdm-agent-unmanage-v1-ed25519` 绑定 tenant/device/registration/generation、
retirement、task/attempt、permit/expiry/deadline 和 Policy 授权；不携带脚本或删除路径。
Agent 仅对本安装身份执行，Offer 不授权卸载，必须取得 Start。
`unmanage_result` 区分 completed、failed、unknown；响应丢失不能推定 completed。
服务端与 Agent 消费者必须使用同一固定公开 revision，不保留旧结构解析。

普通结果属性复用 rows/FieldValue，有界保留且不扩大采集授权；可信资产解释归 Inventory/Resource。
SelfService 文案位于开放 presentation，核心授权、任务与签名结构保持明确。
当前字段切换与未知 key 编辑要求见 [Agent 接入](../../docs/guides/agent-integration.md#当前扩展对象与一次性字段切换)。

Agent 安装包目录描述安装文件与 releaseId；注册 installation 仅引用当前 releaseId。注册配置验签、稳定服务身份与可变 origins 仍归注册协议，不再消费构建期候选 manifest、包内公钥或候选摘要。安装器代码签名由目标操作系统策略决定。
