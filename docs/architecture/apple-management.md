# Apple 原生管理设计

产品拥有 Rust Apple 通道、身份、注册、采集和结果；step-ca 仅负责外部 SCEP 签发。复用 Execution/CollectionRun/Observation/Inventory，避免第二套队列与设备状态权威。

组织身份由 Apple 产品 owner 单源持有，账户驱动与 ADE 各自持有配置和授权。ADE server token 使用独立 RSA/S-MIME 密钥并绑定租户/组织/版本加密；外部 HTTP 不持有业务行锁。ADE journal 仅持有 Apple 控制面操作，现有 runtime 执行每次一页/一效果，不新增设备任务框架。完成时重验 server revision、token revision 和租约；组织内未知外部写必须先只读恢复，不能覆盖或盲目重发。同步页面放入每操作隔离的暂存目录，最终页事务发布并推进 cursor；只有完整全量结果可证明目录缺席。

ADE 原生请求必须通过 Apple 根链/CMS 验证并匹配当前序列号、UDID、profile 分配和新鲜组织目录。注册 authority 固定为 apple_ade 服务主体，pending 事务、SCEP challenge、证书通知与首次 mTLS 都重新检查组织授权。MachineInfo 无 nonce，不把签名解释为防重放证明；实际一次性准入沿用现有 challenge/CSR/注册绑定。成功绑定的设备不依赖 ADE token 持续有效，续期保留冻结的 removal 行为，撤销与退役仍由唯一 registration owner 持有。同步/分配成功、证书签发、首次 check-in 与真实 Setup Assistant/T3 分别记录。

一次性 challenge 先事务提交消费再返回 allow，重复回调不能再次授权。签名模板使用产品授权主题并绑定公钥与 attempt，不信任任意 CSR 主题。通知丢失可由首次匹配的 mTLS 叶证书恢复；签发响应丢失则新授权、新 attempt、新密钥，不能透明重签。

APNs 只是唤醒，不推进命令。关联 ACK 记录接收，完整且认证的 ProfileList 记录产品 Profile 存在性，两者都不能证明 OS 防火墙效果。采集由 CollectionRun 独立关联和封存，不把 DeviceInformation 伪装成状态型命令。

设备/用户通道共用绑定的设备证书，原生 UserID 只标识注册世代内的用户 scope，不建立账户目录。各通道分别持有加密 push 材料、token revision 与租约；Profile ownership 同样按 scope 隔离。一个通道的 token 失效不撤销其他通道的收发资格。CheckOut 和注册退役原子清理全部通道及 Bootstrap escrow。Bootstrap 仅在已接受的 ADE/监督/device enrollment 证据下提供。

token revision 与租约隔离旧 APNs 回执，旧 410 不得清除新 token；配置拒绝持久暂停，短暂网络失败持久退避。健康状态区分内部故障、配置拒绝和设备离线，不能把重试伪造成业务进度。

设备续期复用一次性签发与原生 attempt，保持稳定 profile 身份和注册世代；只有新密钥首次 mTLS/UDID 证明才替换凭据并隔离旧凭据。通用 CA renewal 保持关闭，离线跨过到期须人工重新注册。真实 Mac 的 profile 更新与证书生命周期仍需设备验收。

Apple 纯核心持有版本/条件编译、结果解释、Profile 组合/清单与 guards 规则；通道 adapter 只持有协议和其存储，Execution 继续持有共同资格、执行结算与事务。Profile 错误后的完整反向证据只释放本次失败预留，旧安装 guards 保留；部分或加密清单保持未知。Profile、push、collection 和结果读取端口按真实消费者收窄，复用一个 adapter 与现有 attempt 流。命令查询完成、原生 ACK、待重启/延后/Unknown 与真实效果分别保存。原生观察与读事实由 Apple 核心单源解释，通道负责保护材料读取与字段隐藏，Execution 组合共同状态和读取授权，management HTTP 持有最终响应投影。

DDM 沿用同一 Execution 事务与设备锁。共同层只消费资格、类型化结算和原生投影；Apple channel 持有声明发布、密文报告、ProfileList 原文及尝试关联，纯核心持有原生编译、完整性与声明状态解释。配置输入必须形成自己的闭合引用图；共用相同原生内容的 Policy 持有同一配置单元，不因最初作者退出而撤回另一有效分配的声明。

原生集合按租户、注册、世代和设备/用户通道隔离。服务器 token 绑定内容版本，集合 token 绑定作用域；重启从不可变密文恢复相同发布。当前授权在发布、同步、状态处理和资产读取时复核；失去授权退出集合。Policy retain 只在原冻结 grant 仍有效时维持发布。最后分配退出后，服务器撤回并收到 ACK 可释放逻辑 claim，终端对象缺席和原生设置效果仍独立记录。

StatusReport 没有可用于判定生产先后的原生序号。原生 ServerToken 的冻结版本绑定 publication operation 身份，调用方复用 inputVersion 标签也不能复用旧版本证据；重启与同 operation 重传保持稳定。报告保留接收时的订阅及原生上下文，按精确 identifier/server-token 关联；重复报告幂等，旧版本不修改当前声明。原始历史独立保留，在线处理只折叠新证据并在同一事务保存加密累计状态；查询和重启恢复不重放历史。每作用域最多 16 个有效 publication，每个累计状态最多 512 KiB，超出状态预算后保留原始证据并明确 Unknown，直到新版本重新建立证据。增量数组按原生 identifier 合并非重叠事实；同版本的更新、移除或完整集合省略互相矛盾时保留 Unknown，不按接收时间决定胜者。原生 valid/active/reasons、同步进度、设置效果与合规分开呈现。

Legacy Profile 只从受保护的不可变 Resource 下载，使用已验证的 schema 及真实目标条件编译。Mac 不返回 IsManaged；接管先核对加密保留的关联 ProfileList 请求确实为 ManagedOnly=true，再要求管理清单证明根和所有子载荷的类型、标识、UUID、数量和顺序一致；有效且激活的精确声明版本交接经典所有权。DDM guard 在撤回后继续存在，只能由发出时已关联该 guard 的独立完整 ProfileList 缺席证明释放；新的撤回不借用旧查询结果。

操作、外部 CA 与恢复见 [Apple 指南](../guides/apple-management.md)。参考 [Apple 证书管理](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)、[APNs 响应](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)。

资产采集使用六类固定只读 adapter：DeviceInformation、InstalledApplicationList、SecurityInfo、ProfileList、CertificateList、UserList。每次运行先以自身的设备通道前置查询取得真实 OS、监督、硬件与登记事实，再冻结原生编译上下文；返回时重新检查当前权限。用户模板必须提供规范化 Apple UserID，派发、APNs、回执、dataset、结果与分页游标均绑定此 scope。设备搜索、分组和合规按显式范围选择器独立求值，再按量词归约，不拼接不同用户事实。用户详情、列表与运行详情通过 `scope` JSON 选择；历史用户范围读取不要求通道当前有效，仍检查当前读取权限。详细范围与规则契约见[资产采集](../guides/assets.md#macos-agent-声明式采集)。UserList 仍为监督设备通道能力。

原生可选属性使用有类型的 Record，缺席保持缺席；完整空列表与未返回列表分别处理。Profiles/Certificates 标准包明确为 ManagedOnly；证书在内存解析，仅保留指纹、序列号及有效期等元数据。普通采集响应在原始字节完成认证与重放 MAC 后，只留存固定白名单投影。FileVault 恢复材料、Profile PayloadContent、证书 DER 和未声明扩展键不进入普通资产结果。

DDM 新报告在原事务内封存 Partial CollectionRun，并由现有 Observation 管线交付；重复报告不分配新序号。报告绑定注册代次、UserID、订阅、publication 身份与声明 token。数组必须具有对应状态项的完整基线，增量或无序冲突产生显式 Unknown；Unknown 更新当前状态并独立保留 last_known，不将后到报告解释为较新设备事实。更新状态只作为资产证据，不生成更新执行操作。

官方 macOS v2 包提供经典 NativeCollection 和 DDM Configuration 两类真实内容。DDM 配置包含状态订阅和 activation；实例化后走普通 Resource/Content/Policy 生命周期。Resource 在创建时固化 blueprint ID、版本和初始摘要，目录移除后仍能读取来源。macOS v1、旧 Blueprint DTO、旧 Resource aggregate header 与旧 Inventory 投影格式不提供兼容读取；安装器按现有精确格式准入拒绝不匹配安装，不自动修改历史校验和或清空租户数据。
