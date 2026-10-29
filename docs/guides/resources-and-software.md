# 资源与软件发布

Resource 持有唯一不可变软件定义，企业目录持有来源与版本准入，Policy 持有设备分配，Run/Attempt 持有执行事实，publication/reconcile 持有导出、发布与恢复事实。Script 执行见[企业任务](enterprise-tasks.md)。仅支持全新安装；当前软件模型、接口、初始化 SQL 和当前 Agent wire 直接替换，不提供历史解码或迁移。

## 软件定义与生命周期

`Resource.Software.definition` 的共同部分为来源快照、包和精确生态版本、原始来源证据、完整材料集合、签名要求、重启/降级策略、精确依赖和导出元数据。`behavior` 是闭合 MSI、PKG、Bundle、WinGet、Brew、EXE、DMG、MSIX 变体；格式由行为派生。完整契约以 `rss-mdm-resource::SoftwareSpec` 和当前 Agent wire schema 为准。

EXE 固定安装/升级/卸载调用、完整离线文件布局和独立检测。DMG 明确一个 volume，以及 AppCopy 或 ContainedPkg；应用身份和目标名称不能由扫描猜测；AppCopy 使用完整 DMG 长度/SHA-256，不要求 App 目录摘要。内含 PKG 仍声明单文件长度/SHA-256。MSIX 明确 Package 或 Bundle、精确包/依赖/member 身份以及 TargetUserRegistration 或 DeviceProvisioning，两者不能互相满足结果。原生行为没有脚本兜底；脚本只出现在明确的 Bundle 或受控检测中。

完整长度/SHA-256 是内容基本检查。未签名内容可以启用；需要签名时必须显式冻结 mechanism/publisher，变更要求会改变摘要。启用不代表已通过 Windows/Apple 信任检查。服务端可从 MSIX 固定清单辅助识别元数据，不逐成员解压、验证子包或调用平台安装及信任工具。发布与安装使用管理员明确提交的完整定义，不以服务端解析成功作为额外准入条件。DMG 内部声明仍须由设备执行端核实。

所有材料、行为、依赖、来源证据和导出元数据参与冻结摘要。同版本不得换字节，生命周期绑定不能用于另一份定义。软件版本保存为草稿，Enable 或 Publish 经当前权限、完整文件绑定及定义合法性检查后才可用；Resource.Active 只表示资源默认版本，不决定软件可用性，Archived 仍禁止使用；撤回阻止新准入、下载和启动，不自动卸载。历史回执和未知事实保留。已授权任务可处理匹配的用户已有安装；目标已满足可无修改完成，核实成功不代表本次发生安装，也不伪造历史安装来源或原生管理状态。

管理写使用 `operationId`、`expectedRevision` 和 `input`；相同身份重放相同请求，更换内容冲突。以下路径位于 `/api/v1`：

| 路径 | 行为与权限 |
|---|---|
| `/software/sources/{id}/revisions/{revision}` | GET SoftwareRead；POST register/enable 需要 SoftwareWrite，disable 需要 SoftwareWithdraw |
| `/software/imports` | POST 精确来源转换；需要 SoftwareWrite 和 ResourceWrite |
| `/software/resources/{id}/versions/{version}` | GET SoftwareRead；POST enable/withdraw 分别需要 SoftwareWrite/SoftwareWithdraw |
| `/software/resources/{id}/versions/{version}/content` | SoftwareRead 读取当前已准入的精确变体与 artifact 引用 |

来源注册为 `definition: {id, revision, protocol}`，protocol 是闭合 `private`、`winget_rest`、`winget_community`、`brew_tap`。REST 固定 location/identifier，社区和 Tap 固定 repository/完整 commit，Tap 还固定 owner/tap。注册返回的 `snapshot` 原样进入定义。注册来源立即启用；enable/disable 切换可用性且增加生命周期代次，来源定义变更使用新 revision。版本 enable/withdraw 不接受人工审批 evidence。

## 导入与内容

导入请求冻结 Resource/version、来源 snapshot、精确包版本、平台/架构/变体、选择器、全部产物长度、精确依赖和企业行为补充。REST 与社区 YAML 分别转换；不回退 latest 或公共同名包。转换器版本及原始材料引用和摘要进入定义，原字节保存到既有内容仓。重试先查原操作回执，提交时重新核对来源及依赖准入。

Brew 使用完整消费的受限静态解析，不执行 Ruby。只接受固定 app/pkg Cask 或明确的预构建 bottle 子集；未知 hook、动态插值、源码构建、缺少精确依赖均拒绝。当前固定社区/Tap 文件读取支持 GitHub commit 的受控 raw HTTPS 路径；其他 repository 读取返回 Unsupported。

`content.imports` 按来源 ID 配置受控 `{base, addresses, private_ca}`：固定解析地址、证书与主机名验证、无代理/重定向/凭据转发。注册来源本身不扩大网络白名单。产物声明 origin 后可调用既有 `/content/mirror`，逐个镜像完整对象，提交前重新核对当前生命周期。

以下内容路径位于 `/api/v1/resources/{id}`，写入需要 ResourceWrite：

- `POST /content?version=...&variant=...&platform=...&architecture=...&operation=<UUID>` 完整流式上传；多材料使用 `artifact=<reference>`。
- `POST /uploads/{uploadId}` 建立同样绑定；`GET /uploads/{uploadId}` 查询 offset。
- `PATCH /uploads/{uploadId}?offset=N` 顺序追加；错误 offset 返回 409。
- `POST /uploads/{uploadId}/complete` 完整 hash/长度检查、原子落盘及引用/审计/Outbox 提交。
- `GET /content/operations/{operationId}` 用 ResourceRead 核实原操作回执。

文件落盘不表示数据库提交或启用。CommitUnknown 保留 operationId 查询/重放，不换键。下载支持单段 Range、ETag、If-Range 和 416；每个新请求重新授权，客户端仍核对完整 hash/长度。上传与辅助解析临时文件共享跨进程磁盘预算；辅助解析预算不足时跳过解析，完整性通过仍可保存、启用和分发。

RSS Bundle 的 manifest 位于 `behavior.manifest`，entries 声明普通成员长度/hash。Windows 固定 install.ps1，macOS 固定 install.sh；卸载同样明确 entry。上传完成时校验原文件完整性，小包可从 ZIP `manifest.json` 辅助识别声明目标；不逐成员解压或计算成员摘要，也不承诺服务端验证了所有安装内容。目录定位与默认元数据读取受资源预算限制；超限或缺少必需文件只使辅助解析失败。终端在使用前负责安全解包、内容验证和执行结果核实。

## 派生导出、自托管与恢复

发布请求引用精确 Resource/version/resourceDigest、expectedResourceRevision 和实际 target/targetDigest；服务端校验并固定导出内容，在同一事务内创建发布记录、首个尝试、源执行意图及审计。一个合法目标即可工作，各目标独立发布。manifest/Recipe 由定义派生，没有独立编辑入口；Bundle/MSIX 或无法完整表达的行为返回 Unsupported，EXE→WinGet、DMG→Brew 仅支持受限可表达子集。

`GET /software/sources` 分页发现来源修订，`GET /software/publication-targets` 返回可选实际目标及摘要；`GET /software/publications` 支持目标、资源、版本和 operationId 筛选。目录均返回 items/nextCursor，默认 20、最多 100 项；来源读取需要 SoftwareRead，目标和发布记录读取需要 ReleaseRead。目录可见不代表发布已获授权。目录统一使用 `filter/sort/fields/limit/cursor`，例如
`/software/sources?filter=state==enabled;protocol==private&sort=id,-revision&limit=20`。
来源每个修订独立一行，续页键为 id/revision；发布保留 outcome、withdrawn 和 withdrawal 各自含义，
不开放对发布文档或任意 JSON 路径的查询。目标目录只接受其声明的 id/protocol 字段，拒绝无关参数。
`GET /software/resources/{id}/versions` 从 Resource 聚合分页发现版本及 Resource 状态，默认 64、最多 1000 条；
Resource 状态不代替软件准入/撤回判定，详情和执行仍由原 owner 验证。

`POST /software/publications` 使用 operationId、expectedRevision=0 和 input.action=publish，一次提交即受理发布，返回 202 和持久记录。记录 ID 等于原创建 operationId。草稿自动启用需要 SoftwareWrite 与 ReleasePublish，已启用版本只需 ReleasePublish；已撤回版本必须显式 Enable。`GET /software/publications/{id}` 查询实际结果；同路径 POST recover/retry 使用 ReleaseRecover，withdraw 使用 ReleaseWithdraw，携带 operationId 与当前 expectedRevision。attempt、发布摘要和目标绑定由服务端读取。Unknown 核对原身份，明确 NotApplied 才允许 Retry；源发布成功不代表设备安装成功。

单目标撤回只阻止该发布的新消费，并原子登记下架意图。版本全局撤回在目录生命周期事务内登记全部对应发布的下架意图；后台复用原 worker 推进，不自动卸载。已发生的成功和未知结果保留，其他目标的独立撤回互不影响。目标摘要仅绑定本目标配置，增加另一目标不会修改既有发布身份。

WinGet 由 rss-mdm 公开只读托管，挂载 `/api/v1/software/native/sources/{source}/`：information、manifestSearch、精确 packageManifests，以及 `/exports/{publication}/` 冻结来源。仅启用并发布的内容可读取，响应 no-store。发布/撤回直接更新本地事务和投影，不 HTTP 调用自己。没有 Entra、代理或认证占位；WinGet 配置的 credentials 必须为空。

Brew 将专用系统 Git bare 仓库固定映射到实际来源，生成无父提交的不可变 Tap，保留 bottle/token/依赖布局，Formula 的 source install 明确拒绝。`/exports/{publication}.git` 只提供固定 namespace 的 upload-pack，不提供 receive-pack、任意 SHA want 或通用 Git 服务。只有 Brew 使用来源范围只读 credential_reference；秘密来自宿主配置，wire 只包含引用。撤回移除该快照的读取权，不影响其他版本或包。

配置的 native base 与 artifacts_base 必须匹配 product_origin 下实际挂载。`publication.sources` 是固定仓库/来源装配，导入网络仍由 content.imports 单独控制，见[配置示例](../../fixtures/mdm-config.example.json)。

生命周期 worker 每页最多扫描 32 条既有未完成记录，调用原 reconcile；扫描公平分页、单来源有界预算。CommitUnknown 或 Git 外部结果未知保留原 publication/attempt、目标 commit 与调用身份；不新增通用任务表或恢复状态机。旧 attempt 不阻断当前工作。撤回只约束新的托管读取，不能清除已下载对象、客户端缓存或自动卸载。

Native Policy 明确 `delivery: {kind: native, target}`，直接材料则为 `delivery: {kind: direct}`。Policy 软件动作只提交资源、版本、变体和部署意图，不接受 admissionOperation；后台冻结完整依赖闭包的生命周期绑定。版本撤回或来源停用后，即使重新启用，旧 Policy/Offer/安装包绑定也不会恢复有效，需重新提交。Offer 冻结 publication、targetDigest、resourceDigest、definitionDigest、documentSha256、精确依赖、全部材料 URI 及 Brew commit；Start 用同一个准入判断重新核对，来源撤回或执行上下文变化拒绝旧 Offer。设备执行由独立 Agent 持有，服务端发布成功不代表安装成功。

## 部署与更新

普通安装包使用 Direct Policy，不要求配置或发布 WinGet/Brew 源。更新通过修改现有 Policy 的精确资源版本完成；新版本发布不自动改变旧策略。RequiredInstall 表示达到指定版本，未安装设备也可能安装；AvailableInstall 保持自助安装。升级与降级遵循软件定义，不能将安装策略等同于“只更新已安装软件”的补丁服务。

同一源、同一版本可按设备 Scope 分批部署。每批配置 UTC opensAt，可选 minimumVerifiedPercent 对上一批已核实成功比例设门槛；时间满足且门槛达标后自动获得准入资格。统计未就绪、样本为空、Pending/Unknown、离线或待重启均不能冒充成功。每批受总 Scope 约束，重叠设备归最早阶段；暂停 Policy 阻止后续准入。一次全量部署复用单阶段，不要求管理员设置灰度。这里的设备阶段不改变软件源或发布记录，也不触发自动回滚。

单目标配置示例（位于 publication.sources，导入来源仍独立配置）：

```json
[{"name":"internal","credentials":{},"target":{"Winget":{"base":"https://mdm.example/api/v1/software/native/sources/internal/","artifacts_base":"https://mdm.example/api/v1/software/native/sources/internal/artifacts/"}}}]
```

## 来源与证据边界

WinGet fixture、schema 与许可见[fixture 来源](../../crates/winget-source/tests/fixtures/README.md)。参考 [WinGet REST contract](https://github.com/microsoft/winget-cli-restsource/blob/21cd5dda3dab39aa059f4d34914959736af7ee70/documentation/WinGet-1.0.0.yaml)、[Homebrew 固定源码](https://github.com/Homebrew/brew/tree/7cce6eac8d897b0b8440e16f33dbcb21770da7cf) 和 [Git namespace](https://github.com/git/git/blob/v2.51.0/Documentation/gitnamespaces.adoc)。安装和恢复见[运维](../deployment/operations.md)。真实 Windows WinGet 源接入、精确解析和产物获取须由 Windows 环境补证；后端验收不代替该证据。

Brew 派生只接受能保留冻结行为的子集：PKG/DMG 的 system scope、无额外参数或环境、标准退出码和 in-place 升级；PKG/ContainedPkg 的显式卸载必须为 null，导出不合成 pkgutil 卸载。AppCopy 必须明确允许删除声明的精确目标；授权来自当前可信任务和执行上下文，不依赖历史安装来源。Bottle 使用非 root 用户、相同安装/升级调用及明确的原生卸载；其它行为返回 Unsupported。MSIX Bundle 的实际 manifest 成员必须与完整冻结声明相等；未声明 application/resource 成员均拒绝。

## 管理员下载脚本原文

`GET /api/v1/resources/{id}/versions/{version}/script?platform=macos&architecture=aarch64&variant=default`
以当前 ResourceRead 权限读取精确不可变 Script 产物。错误资源类型、归档版本、失效引用或越权均拒绝；下载前校验完整摘要与长度。
返回附件原始字节，支持既有 Range/ETag，并禁止共享缓存。上传者身份不是读取授权，脚本内容不会写入审计。

## 从公共源准备测试安装包

公共源导入与直接分发是两个入口。WinGet/Homebrew 可用于查找上游安装包，
下载并完整校验后也可按前文的 Direct Policy 上传分发；这条路径不要求托管发布目标，
不代表已验证 RSS 的公共源转换或 WinGet/Brew 原生执行。

Windows 可先用 `winget search`、`winget show --id <ID> --exact --source winget`
确认精确版本，再下载匹配设备架构的文件：

```powershell
winget download --id <ID> --exact --source winget --version <VERSION> --architecture arm64 --download-directory <DIRECTORY>
```

Homebrew Cask 可用 `brew info --json=v2 --cask <TOKEN>` 查元数据，
`brew fetch --cask <TOKEN>` 只下载到缓存，`brew --cache --cask <TOKEN>` 获取缓存路径。
无需安装 Homebrew 也可读取其[官方 JSON API](https://formulae.brew.sh/docs/api/)，
从精确 Cask 元数据取得上游 URL 与 SHA-256。Formula 的源码归档和 bottle 不是通用 macOS PKG；
测试 PKG/DMG 应选择确实提供相应安装包的 Cask。

可复现测试须保存精确版本、架构、原始清单及其 commit、上游 URL、实际字节长度和 SHA-256，
不能只记可变的 latest 地址。旧版升级样本从原项目的固定 release 或公共源固定 commit 获取，
分别记录两个版本的摘要。Bundle 中提取的 MSIX 须保持成员原字节并记录原 Bundle 和成员名；
设备上的签名、依赖及注册/预配检查仍须实际完成。

本地安装包统一放在仓库的 `deployment/software_package/`，该目录被 Git 忽略；
本地 `manifest.json` 与 `SHA256SUMS` 记录文件来源和完整性，
可在该目录执行 `shasum -a 256 -c SHA256SUMS` 复核。
包、原始清单及运行记录均不强制加入 Git；安装包可取得不代表安装或升级成功。
升级验收应先确认旧版已安装，再将同一 Policy 切到新版资源版本，核对实际设备版本及最终回执。
