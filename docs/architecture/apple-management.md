# Apple 原生管理设计

产品拥有身份、注册、采集和结果；step-ca 仅负责外部 SCEP 签发，NanoMDM 仅作协议对照。复用 Execution/CollectionRun/Observation/Inventory，避免第二套队列与设备状态权威。

一次性 challenge 先事务提交消费再返回 allow，重复回调不能再次授权。签名模板使用产品授权主题并绑定公钥与 attempt，不信任任意 CSR 主题。通知丢失可由首次匹配的 mTLS 叶证书恢复；签发响应丢失则新授权、新 attempt、新密钥，不能透明重签。

APNs 只是唤醒，不推进命令。关联 ACK 记录接收，完整且认证的 ProfileList 记录产品 Profile 存在性，两者都不能证明 OS 防火墙效果。采集由 CollectionRun 独立关联和封存，不把 DeviceInformation 伪装成状态型命令。

设备/用户通道共用绑定的设备证书，原生 UserID 只标识注册世代内的用户 scope，不建立账户目录。各通道分别持有加密 push 材料、token revision 与租约；Profile ownership 同样按 scope 隔离。一个通道的 token 失效不撤销其他通道的收发资格。CheckOut 和注册退役原子清理全部通道及 Bootstrap escrow。Bootstrap 仅在已接受的 ADE/监督/device enrollment 证据下提供。

token revision 与租约隔离旧 APNs 回执，旧 410 不得清除新 token；配置拒绝持久暂停，短暂网络失败持久退避。健康状态区分内部故障、配置拒绝和设备离线，不能把重试伪造成业务进度。

设备续期复用一次性签发与原生 attempt，保持稳定 profile 身份和注册世代；只有新密钥首次 mTLS/UDID 证明才替换凭据并隔离旧凭据。通用 CA renewal 保持关闭，离线跨过到期须人工重新注册。真实 Mac 的 profile 更新与证书生命周期仍需设备验收。

Apple 纯核心持有版本/条件编译、结果解释、Profile 组合/清单与 guards 规则；通道 adapter 只持有协议和其存储，Execution 继续持有共同资格、执行结算与事务。Profile 错误后的完整反向证据只释放本次失败预留，旧安装 guards 保留；部分或加密清单保持未知。Profile、push、collection 和结果读取端口按真实消费者收窄，复用一个 adapter 与现有 attempt 流。命令查询完成、原生 ACK、待重启/延后/Unknown 与真实效果分别保存。

DDM 沿用同一 Execution 事务与设备锁。共同层只消费资格、类型化结算和原生投影；Apple channel 持有声明发布、密文报告、ProfileList 原文及尝试关联，纯核心持有原生编译、完整性与声明状态解释。配置输入必须形成自己的闭合引用图；共用相同原生内容的 Policy 持有同一配置单元，不因最初作者退出而撤回另一有效分配的声明。

原生集合按租户、注册、世代和设备/用户通道隔离。服务器 token 绑定内容版本，集合 token 绑定作用域；重启从不可变密文恢复相同发布。当前授权在发布、同步、状态处理和资产读取时复核；失去授权退出集合。Policy retain 只在原冻结 grant 仍有效时维持发布。最后分配退出后，服务器撤回并收到 ACK 可释放逻辑 claim，终端对象缺席和原生设置效果仍独立记录。

StatusReport 没有可用于判定生产先后的原生序号。报告保留接收时的订阅及原生上下文，按精确 identifier/server-token 关联；重复报告幂等，旧版本不修改当前声明。原始历史独立保留，在线处理只折叠新证据并在同一事务保存加密累计状态；查询和重启恢复不重放历史。每作用域最多 16 个有效 publication，每个累计状态最多 512 KiB，超出状态预算后保留原始证据并明确 Unknown，直到新版本重新建立证据。增量数组按原生 identifier 合并非重叠事实；同版本的更新、移除或完整集合省略互相矛盾时保留 Unknown，不按接收时间决定胜者。原生 valid/active/reasons、同步进度、设置效果与合规分开呈现。

Legacy Profile 只从受保护的不可变 Resource 下载，使用已验证的 schema 及真实目标条件编译。Mac 不返回 IsManaged；接管先核对加密保留的关联 ProfileList 请求确实为 ManagedOnly=true，再要求管理清单证明根和所有子载荷的类型、标识、UUID、数量和顺序一致；有效且激活的精确声明版本交接经典所有权。DDM guard 在撤回后继续存在，只能由发出时已关联该 guard 的独立完整 ProfileList 缺席证明释放；新的撤回不借用旧查询结果。

操作、外部 CA 与恢复见 [Apple 指南](../guides/apple-management.md)。参考 [Apple 证书管理](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)、[APNs 响应](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)，协议来源固定于 [Apple fixtures](../../fixtures/apple-tools.lock.json)。
