# 资源与软件发布

Resource 持有不可变 software/script/configuration 版本，Policy 引用意图，软件发布持有审批、外部提交与对账事实。Script 执行见 [企业任务](enterprise-tasks.md)。公共类型、编码与预算以 crate rustdoc 为准。

版本标签是精确身份，不按 SemVer 推断顺序；同版本不能更换字节。激活与弃用改变生命周期而不改内容，归档要求真实引用检查并保留历史。声明产物摘要不证明实际对象存在，提交前必须核对实际长度与摘要。

## 审批、发布与恢复

按 Test → Pilot → Production 顺序，每环重新验证和审批。审批绑定完整平台包、所有变体、源配置、证据及发布者；实际主体来自当前会话，默认禁止同一主体审批并发布。后台源驱动身份不能充当管理员批准。

首次外部操作前同事务保存固定请求、回执意图和审计。外部成功而本地结果未知时保留 publication/attempt 对账，不生成另一份发布。Pending/Unknown 不是失败；只有确认本次未生效且以后也不会生效才允许显式 Retry。隔离/弃用后仍保留迟到结果，不能抹除外部暴露事实。

撤回先明确发布结果，再对账删除。查询不到暂时结果不等于未发布，WinGet 删除结果未知不能盲目重发。完成撤回不代表客户端卸载或缓存失效；重新发布须新候选、重新审批，并核对同版本字节与旧尝试竞争。

PG 组合借用同一 runtime/tenant 事务，业务拒绝必须处理，存储错误传播以回滚；状态、回执与 Outbox 原子提交。最外层事务先声明完整 Outbox 分区再取得业务锁。CommitUnknown/RollbackFailed 保留原操作身份，不能借重连换键。

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
