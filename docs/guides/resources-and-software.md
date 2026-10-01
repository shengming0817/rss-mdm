# 资源与软件发布

Resource 持有唯一不可变软件定义，企业目录持有来源与版本准入，Policy 持有设备分配，Run/Attempt 持有执行事实，publication/reconcile 持有导出、发布与恢复事实。Script 执行见[企业任务](enterprise-tasks.md)。仅支持全新安装；当前软件模型、接口、初始化 SQL 和 Agent V4 shape 直接替换，不提供历史解码或迁移。

## 软件定义与批准

`Resource.Software.definition` 的共同部分为来源快照、包和精确生态版本、原始来源证据、完整材料集合、签名要求、重启/降级/所有权策略、精确依赖和导出元数据。`behavior` 是闭合 MSI、PKG、Bundle、WinGet、Brew、EXE、DMG、MSIX 变体；格式由行为派生。完整契约以 `rss-mdm-resource::SoftwareSpec` 和当前 Agent wire schema 为准。

EXE 固定安装/升级/卸载调用、完整离线文件布局和独立检测。DMG 明确一个 volume，以及 AppCopy 或 ContainedPkg；应用身份、目标名称与材料摘要不能由扫描猜测。MSIX 明确 Package 或 Bundle、精确包/依赖/member 身份以及 TargetUserRegistration 或 DeviceProvisioning，两者不能互相满足结果。原生行为没有脚本兜底；脚本只出现在明确的 Bundle 或受控检测中。

完整长度/SHA-256 是内容基本检查。未签名内容可以批准；需要签名时必须显式冻结 mechanism/publisher，变更要求会改变摘要。批准不代表已通过 Windows/Apple 信任检查。服务端核对 MSIX 的实际 XML 命名空间、包身份、依赖和选定 bundle member 字节，不调用平台安装或信任工具。DMG 内部声明仍须由设备执行端核实。

所有材料、行为、依赖、来源证据和导出元数据参与冻结摘要。同版本不得换字节，旧批准不能批准另一份定义。Resource.Active 或 Published 不能代替企业批准；撤回阻止新准入、下载和启动，不自动卸载。历史回执和未知事实保留。

管理写使用 `operationId`、`expectedRevision` 和 `input`；相同身份重放相同请求，更换内容冲突。以下路径位于 `/api/v3`：

| 路径 | 行为与权限 |
|---|---|
| `/software/sources/{id}/revisions/{revision}` | GET SoftwareRead；POST register/approve/withdraw 分别需要 SoftwareWrite/SoftwareApprove/SoftwareWithdraw |
| `/software/imports` | POST 精确来源转换；需要 SoftwareWrite 和 ResourceWrite |
| `/software/resources/{id}/versions/{version}` | GET SoftwareRead；POST approve/withdraw 分别需要 SoftwareApprove/SoftwareWithdraw |
| `/software/resources/{id}/versions/{version}/content` | SoftwareRead 读取当前已准入的精确变体与 artifact 引用 |

来源注册为 `definition: {id, revision, protocol}`，protocol 是闭合 `private`、`winget_rest`、`winget_community`、`brew_tap`。REST 固定 location/identifier，社区和 Tap 固定 repository/完整 commit，Tap 还固定 owner/tap。注册返回的 `snapshot` 原样进入定义。批准与撤回需要非空 evidence；来源定义变更使用新 revision。

## 导入与内容

导入请求冻结 Resource/version、来源 snapshot、精确包版本、平台/架构/变体、选择器、全部产物长度、精确依赖和企业行为补充。REST 与社区 YAML 分别转换；不回退 latest 或公共同名包。转换器版本及原始材料引用和摘要进入定义，原字节保存到既有内容仓。重试先查原操作回执，提交时重新核对来源及依赖准入。

Brew 使用完整消费的受限静态解析，不执行 Ruby。只接受固定 app/pkg Cask 或明确的预构建 bottle 子集；未知 hook、动态插值、源码构建、缺少精确依赖均拒绝。当前固定社区/Tap 文件读取支持 GitHub commit 的受控 raw HTTPS 路径；其他 repository 读取返回 Unsupported。

`content.imports` 按来源 ID 配置受控 `{base, addresses, private_ca}`：固定解析地址、证书与主机名验证、无代理/重定向/凭据转发。注册来源本身不扩大网络白名单。产物声明 origin 后可调用既有 `/content/mirror`，逐个镜像完整对象，提交前重新核对当前批准。

以下内容路径位于 `/api/v3/resources/{id}`，写入需要 ResourceWrite：

- `POST /content?version=...&variant=...&platform=...&architecture=...&operation=<UUID>` 完整流式上传；多材料使用 `artifact=<reference>`。
- `POST /uploads/{uploadId}` 建立同样绑定；`GET /uploads/{uploadId}` 查询 offset。
- `PATCH /uploads/{uploadId}?offset=N` 顺序追加；错误 offset 返回 409。
- `POST /uploads/{uploadId}/complete` 完整 hash/长度检查、原子落盘及引用/审计/Outbox 提交。
- `GET /content/operations/{operationId}` 用 ResourceRead 核实原操作回执。

文件落盘不表示数据库提交或批准。CommitUnknown 保留 operationId 查询/重放，不换键。下载支持单段 Range、ETag、If-Range 和 416；每个新请求重新授权，客户端仍核对完整 hash/长度。上传与 MSIX 嵌套 member 临时文件共享跨进程磁盘预算；超过预算拒绝，不无限解包。

RSS Bundle 的 manifest 位于 `behavior.manifest`，ZIP `manifest.json` 为规范紧凑 JSON；entries 明确全部普通成员长度/hash。Windows 固定 install.ps1，macOS 固定 install.sh；卸载同样明确 entry。拒绝穿越、大小写冲突、重复成员、链接、加密、未声明文件、重叠布局、尾随数据和数量/展开预算超限。

## 派生导出、自托管与恢复

发布候选请求只引用冻结的 Resource/version/resourceDigest、expectedResourceRevision 与目标来源。manifest/Recipe 是派生制品，没有独立可写 Submission。导出 identity 绑定 tenant、来源配置、ring、完整定义、依赖、文档及材料。Bundle/MSIX、签名要求或无法完整表达的行为返回 Unsupported；EXE→WinGet、DMG→Brew 只支持受限可表达子集。

Test → Pilot → Production 每环重新验证和审批，默认分离批准者与发布者；后台驱动不充当管理员批准。发布与撤回使用现有事务、锁、审计、Outbox 和投影。

WinGet 由 rss-mdm 公开只读托管，挂载 `/software/native/sources/{source}/{ring}/`：information、manifestSearch、精确 packageManifests，以及 `/exports/{publication}/` 冻结来源。仅明确批准并发布的内容可读取，响应 no-store。发布/撤回直接更新本地事务和投影，不 HTTP 调用自己。没有 Entra、代理或认证占位；WinGet 配置的 credentials 必须为空。

Brew 将专用系统 Git bare 仓库固定映射到来源/ring，生成无父提交的不可变 Tap，保留 bottle/token/依赖布局，Formula 的 source install 明确拒绝。`/exports/{publication}.git` 只提供固定 namespace 的 upload-pack，不提供 receive-pack、任意 SHA want 或通用 Git 服务。只有 Brew 使用来源范围只读 credential_reference；秘密来自宿主配置，wire 只包含引用。撤回移除该快照的读取权，不影响其他版本或包。

配置的 native base 与 artifacts_base 必须匹配 product_origin 下实际挂载。`flow.publication.sources` 是固定仓库/来源装配，导入网络仍由 content.imports 单独控制，见[配置示例](../../fixtures/mdm-config.example.json)。

生命周期 worker 每页最多扫描 32 条既有未完成记录，调用原 reconcile；扫描公平分页、单来源有界预算。CommitUnknown 或 Git 外部结果未知保留原 publication/attempt、目标 commit 与调用身份；不新增通用任务表或恢复状态机。旧 attempt 不阻断当前工作。撤回只约束新的托管读取，不能清除已下载对象、客户端缓存或自动卸载。

Native Policy 明确 `delivery: {kind: native, source, ring}`，直接材料则为 `delivery: {kind: direct}`。Offer 冻结 publication、sourceDigest、resourceDigest、definitionDigest、documentSha256、精确依赖、全部材料 URI 及 Brew commit；Start 用同一个准入判断重新核对，来源撤回或执行上下文变化拒绝旧 Offer。设备执行由独立 Agent 持有，服务端发布成功不代表安装成功。

## 来源与证据边界

WinGet fixture、schema 与许可见[fixture 来源](../../crates/winget-source/tests/fixtures/README.md)。参考 [WinGet REST contract](https://github.com/microsoft/winget-cli-restsource/blob/21cd5dda3dab39aa059f4d34914959736af7ee70/documentation/WinGet-1.0.0.yaml)、[Homebrew 固定源码](https://github.com/Homebrew/brew/tree/7cce6eac8d897b0b8440e16f33dbcb21770da7cf) 和 [Git namespace](https://github.com/git/git/blob/v2.51.0/Documentation/gitnamespaces.adoc)。安装和恢复见[运维](../deployment/operations.md)。真实 Windows WinGet 源接入、精确解析和产物获取须由 Windows 环境补证；后端验收不代替该证据。
