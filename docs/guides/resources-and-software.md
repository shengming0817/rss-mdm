# 资源与软件发布

Resource 持有不可变 software/script/configuration 版本，Policy 引用意图，企业目录持有来源/版本准入，外部软件发布分别持有发布审批、提交与对账事实。Script 执行见 [企业任务](enterprise-tasks.md)。公共类型、编码与预算以 crate rustdoc 为准。

版本标签是精确身份，不按 SemVer 推断顺序；同版本不能更换字节。激活与弃用改变生命周期而不改内容，归档要求真实引用检查并保留历史。声明产物摘要不证明实际对象存在，提交前必须核对实际长度与摘要。

## 企业目录与批准

私有 MSI、PKG 和 RSS Bundle 直接创建 Resource.Software；无需伪造 WinGet/Brew 清单。软件声明只有 `definition`，完整数据类型见 `rss-mdm-resource::SoftwareSpec`。旧 install/detect/uninstall 标识字段与旧软件持久编码已删除，无历史导入或双格式读取。

定义冻结精确来源快照、包与版本、平台/架构变体、安装/卸载/检测、解释器、执行身份、字面参数/环境、预算、重启/降级/所有权策略、精确依赖及所有产物长度/SHA-256。软件版本是生态原文，不解析 latest 或隐式 SemVer 范围。辅助脚本及 Brew source/bottle/dependency 产物也必须进入 Resource 定义；发布请求不能额外注入未冻结内容。

管理写操作使用 `operationId`、`expectedRevision` 和 `input`；同 operation 重放同一请求，改内容冲突。以下路径均位于 `/api/v3`：

| 路径 | 行为与权限 |
|---|---|
| `/software/sources/{id}/revisions/{revision}` | GET 读取；POST `register`（SoftwareWrite）、`approve`（SoftwareApprove）、`withdraw`（SoftwareWithdraw） |
| `/software/resources/{id}/versions/{version}` | GET 读取准入；POST `approve` / `withdraw`，分别需要 SoftwareApprove / SoftwareWithdraw |
| `/software/resources/{id}/versions/{version}/content` | SoftwareRead 读取当前已准入的精确变体内容；查询参数为 platform、architecture、variant，可指定 artifact 引用 |

读取源与版本准入需要 SoftwareRead。源注册体为 `definition: {id, revision, kind, location, publishers}`；kind 为 private/winget/brew，private 的 location 为 null，WinGet 为固定 HTTPS 源地址，Brew 为完整 owner/tap。注册返回 `snapshot`，原样进入 SoftwareSpec.source。源定义不可换写，批准或撤回只更新准入状态；变更来源内容须新 revision。批准/撤回必须提供非空 `evidence` 数组。

先批准来源，创建完整 Resource 版本并上传全部产物，再批准该版本。版本批准核对所有变体、来源、产物、检测及有限依赖；Resource.Active 和外部 Published 均不能代替批准。内部批准不强制外部三环；分配和灰度归 #2470。撤回阻断新的安装准入，不隐式卸载；历史操作回执、旧 attempt 及未知事实继续保留。查询或重放旧批准回执不重新产生当前准入。

## 内容上传、续传与镜像

内容配置与签名分离，配置示例和清理规则见[企业任务](enterprise-tasks.md)。以下资源路径均位于 `/api/v3/resources/{id}`，需要 ResourceWrite，并逐次重新核对当前授权和不可变资源版本：

- `POST /content?version=...&variant=...&platform=...&architecture=...&operation=<UUID>` 流式上传完整产物；多产物软件用 `artifact=<reference>` 指定成员。
- `POST /uploads/{uploadId}` 携带相同选择参数，建立绑定当前主体、版本摘要及产物的恢复会话。
- `GET /uploads/{uploadId}` 查询已确认 offset；`PATCH /uploads/{uploadId}?offset=N` 顺序追加字节，错 offset 返回 409 和当前 offset。
- `POST /uploads/{uploadId}/complete` 验证完整长度/hash、原子发布并提交引用、审计及 Outbox；重复完成保持原身份。
- `GET /content/operations/{operationId}` 使用 ResourceRead 查询持久绑定回执，上传临时会话过期后仍可核实原操作。暂时查不到不构成提交失败证明。

文件存在不表示数据库已提交，更不表示软件已批准。CommitUnknown 后保留 operationId 并查询/重放；不得换键掩盖未知结果。下载支持单段 Range、ETag、If-Range 和 416；每个新请求重新授权。审计记录授权读取，不证明客户端完整接收；客户端仍需校验最终长度/hash。

外部导入也使用 Resource.Software，产物可声明不可变 `origin`。`content.imports` 按来源 ID 配置允许的 origin 列表，每项为 `{base, addresses, private_ca}`，沿用受控 HTTPS、固定解析地址、CA 验证、无代理/重定向/凭据转发规则。来源批准后，通过 `POST /content/mirror` 携带与上传相同的选择参数及 operation，只镜像选定产物；同一次流读取完成校验和落盘，不扫描或全量镜像生态。绑定提交前再次核对当前来源批准及精确快照；下载期间撤回来源会拒绝绑定，恢复后使用原 operation 重试。此配置不依赖外部 publication 的三环装配。

## RSS Bundle

一个平台、一个架构对应一个 ZIP。`SoftwareSpec.bundle` 是完整 manifest，ZIP 内 `manifest.json` 使用该结构的规范紧凑 JSON 字节；字段格式以 Resource serde 类型为准。`entries` 明确每个非 manifest 成员的路径、未压缩长度和 SHA-256。

Windows 固定 `install.ps1`，macOS 固定 `install.sh`；仅声明卸载时要求 `uninstall.ps1` / `uninstall.sh`。必须有 MSI product、PKG receipt 或受控脚本检测，不能用安装 exit 0 代替检测。包内脚本和 payload 一同批准，不拆成 Script 资源。

只接收普通文件、便携 ASCII 相对路径，以及 Stored/Deflate 压缩；拒绝路径穿越、设备名、大小写冲突、重复成员、符号链接、加密、未声明成员、重叠布局、尾随数据和预算超限。ZIP64 仍受相同数量与展开限制。服务端不执行包内脚本；平台解压、签名和执行检查仍由 Agent adapter 持有。

## 外部发布审批与恢复

按 Test → Pilot → Production 顺序，每环重新验证和审批。审批绑定完整平台包、所有变体、源配置、证据及发布者；实际主体来自当前会话，默认禁止同一主体审批并发布。后台源驱动身份不能充当管理员批准。

首次外部操作前同事务保存固定请求、回执意图和审计。外部成功而本地结果未知时保留 publication/attempt 对账，不生成另一份发布。软件源调用使用持久调用序号区分确认未发出后的下一次调用；结果记录身份绑定 publication、attempt、观察证据及观察时间，重放保留原身份和精确字节。Pending/Unknown 不是失败；只有确认本次未生效且以后也不会生效才允许显式 Retry。隔离/弃用后仍保留迟到结果，不能抹除外部暴露事实。

撤回先明确发布结果，再对账删除。查询不到暂时结果不等于未发布，WinGet 删除结果未知不能盲目重发。完成撤回不代表客户端卸载或缓存失效；重新发布须新候选、重新审批，并核对同版本字节与旧尝试竞争。

外部 publication 的业务/SQL/恢复位于 software-service，宿主注入凭据和事务内审计；发布配置按来源提供 `credentials: {credentialReference: secretFile}`，源自身只保存 credential_reference。PG 组合借用同一 runtime/tenant 事务，业务拒绝必须处理，存储错误传播以回滚；状态、回执与 Outbox 原子提交。最外层事务先声明完整 Outbox 分区再取得业务锁。CommitUnknown/RollbackFailed 保留原操作身份，不能借重连换键。

## 产物与网络

公开 CDN/S3 稳定 HTTPS 对象使用匿名 GET，不转发源 token。地址、IP、CA 由受控部署批准，请求不能扩展白名单；继续验证证书/主机名、长度、摘要及读取预算。拒绝隐式代理、重定向、内嵌身份和短期签名 URL。公开对象的可读性不由 MDM 元数据 RLS 隐藏。

## WinGet 支持矩阵

仅 REST contract 1.0.0：`GET /information` 和
`GET /packageManifests/{PackageIdentifier}?Version={exact-version}`，带 `Version: 1.0.0`。
源必须明确声明支持该版本，SourceIdentifier 与配置精确一致；不自动降级、搜索公共源或调用 winget。

- installer：MSI/EXE；架构：x64/arm64；scope：user/machine/未声明。
  未声明只能被 `Scope::Unspecified` 匹配，不默认成为 machine。
- 先按 architecture/type/scope 筛候选，可用 `Query::with_installer_id` 指定 InstallerIdentifier；
  不匹配的兄弟 installer 不阻断目标。对匹配候选严格校验行为字段、URL 和摘要；多个结果返回 Ambiguous，
  没有匹配项（包括源只含不受支持的架构或类型）返回 NotFound。
- 单一目标版本、空 channel、默认 locale、无额外 locale；支持 installer 的身份、类型、架构、scope、URL 和 SHA-256。
  switches/dependencies/其他行为字段和未知协议明确 Unsupported；不声称支持完整 WinGet manifest 集合。
- URL 为无内嵌身份、query 或 fragment 的 HTTPS 地址。短期签名 URL 不进入持久元数据。
- `parse_manifest` 验证格式及精确身份；`verify_expected_digest` 比较调用方提供的期望摘要；
  完整 `VersionManifest::parse/from_response` 校验全部 installer 与 License 等发布字段，`bytes()` 返回官方 POST ManifestSchema（无 Data 包装、无空 Channel）。旧单 installer 发布输出已删除。

`Source::new` 接受受信 tenant、精确源身份、以 `/` 结尾的 base URL、经批准的连接 IP 和源凭据引用。
公开源构造只接受 HTTPS，地址由 `reqwest` resolver 固定，禁止重定向/隐式代理及 loopback/link-local/multicast/unspecified。
内部私有 IP 可由产品显式批准。私有 PKI 可调用 `Source::with_root_certificate`，此时仅信任指定 PEM root，
继续验证证书与主机名并使用原 URL 的 SNI；产品负责批准 CA，不支持关闭证书验证。
`Access::new` 必须提供非空 bearer，拒绝空白和非法 token 字符，不支持隐式匿名降级；
每次 query 必须匹配 tenant/source/credential reference，错配在 I/O 前拒绝。此结构不认证调用者。
源 token 不转给产物 URL。凭据解析、地址批准和真实授权由应用组装拥有。
HTTP 状态/transport/timeout 错误携带安全 RequestStage；manifest 404 统一为 NotFound，information 404 保留阶段错误。
查询受统一 deadline 和响应预算约束；错误不携带响应正文或 URL。
## Brew 支持矩阵与本地 Git

只支持完整 `owner/tap/name`、受控 Formula/Bottle 和 `app`/`pkg` Cask；不解析用户 Ruby。
Formula 固定从源归档安装一个命名可执行文件，Bottle 标签仅 `sonoma`/`arm64_sonoma`，
所有 Bottle 使用同一 HTTPS root_url，不声称 `any_skip_relocation`。依赖采用同租户完整 Tap/package 引用，
拒绝重复和自引用；依赖是否已批准及其快照由调用方决定。
Cask 支持 Arm64/Intel 的 URL+SHA-256，单架构显式生成 `depends_on arch`。
pkg 必须提供非空、唯一、精确 pkgutil receipt ID 清单；渲染带锚点且转义的 `uninstall pkgutil`，不接受通配表达式或脚本。
模板转义引号、反斜杠与 Ruby 插值，拒绝 hook、任意 DSL、路径穿越、动态代码及无摘要产物。
渲染顺序稳定，结果为私有构造的 `Document`，最大 1 MiB。

`Repository::open` 仅接受调用方明确授权、与 tenant/Tap 唯一映射的专用本地 SHA-1 bare 仓库；
调用方拥有目录访问控制，库不从目录参数推断认证权威。不得将不同租户映射到同一目录。
不支持工作区 checkout、外部共享 Tap、远端 clone/push 或自动仓库发现。

1. `prepare(base, document, operation, at)` 写 blob/tree/commit，但不更新 ref。
   固定 parent、document、operation、tenant/Tap 与时间可重建同一目标 commit；准备结果暴露 `target()`。
2. `apply(prepared)` 对 `refs/heads/main` 按预期 parent 作 CAS；已是目标返回 AlreadyApplied，
   分支漂移返回 Conflict。使用 no-deref，拒绝符号 ref，不跟随它覆写其他分支。
3. 提交结果未知时保留原输入与目标，重建原 Prepared 后查询/重放；禁止换 operation 或 parent 盲目重试。
   命令报错后重新读取 head：目标已落地返回 AlreadyApplied，head 与原 base 不同返回 Conflict，
   head 未变或无法读取返回 OutcomeUnknown。恢复由应用持久发布状态负责。
4. `read(commit, expected_document)` 固定完整 commit，核对路径 mode、blob 字节和内容摘要；
   分支前移不改变旧快照。Snapshot 是核对结果，不是远端发布回执。

使用 `/usr/bin/git` 参数调用，禁 hooks、懒加载、全局配置和隐式环境，单次命令 10 秒预算；
超预算输出终止并回收子进程。GitFailure/GitTimeout 包含安全操作阶段与可用退出码；明确缺少对象返回 NotFound，绝不透传 stderr。Brew 的未接线 AccessBinding 已删除；专用仓库目录的访问权限由受控服务进程拥有。库不执行 Ruby、brew 或安装动作。
`prepare_remove` 只从指定 base 删除匹配的受控定义，`presence` 与 `contains_commit` 区分准备对象和已进入分支历史的提交。源撤回、产物保留和外部结果对账由应用发布 owner 持有。

## 来源

WinGet 样本、schema 提取过程与许可见 [fixture 来源](../../crates/winget-source/tests/fixtures/README.md)。Brew 格式参考 [Homebrew 固定源码](https://github.com/Homebrew/brew/tree/4ef2edc123233e30f94c4a6d21bcb019806f1945)，Git CAS 参考 [Git refs.c](https://github.com/git/git/blob/v2.51.0/refs.c)。安装和故障诊断见 [运维](../deployment/operations.md)。源 Published 不表示设备安装成功。
