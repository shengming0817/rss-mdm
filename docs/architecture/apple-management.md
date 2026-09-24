# Apple 原生管理设计

产品拥有身份、注册、采集和结果；step-ca 仅负责外部 SCEP 签发，NanoMDM 仅作协议对照。复用 Commands/CollectionRun/Observation/Inventory，避免第二套队列与设备状态权威。

一次性 challenge 先事务提交消费再返回 allow，重复回调不能再次授权。签名模板使用产品授权主题并绑定公钥与 attempt，不信任任意 CSR 主题。通知丢失可由首次匹配的 mTLS 叶证书恢复；签发响应丢失则新授权、新 attempt、新密钥，不能透明重签。

APNs 只是唤醒，不推进命令。关联 ACK 记录接收，完整且认证的 ProfileList 记录产品 Profile 存在性，两者都不能证明 OS 防火墙效果。采集由 CollectionRun 独立关联和封存，不把 DeviceInformation 伪装成状态型命令。

token revision 与租约隔离旧 APNs 回执，旧 410 不得清除新 token；配置拒绝持久暂停，短暂网络失败持久退避。健康状态区分内部故障、配置拒绝和设备离线，不能把重试伪造成业务进度。

设备续期复用一次性签发与原生 attempt，保持稳定 profile 身份和注册世代；只有新密钥首次 mTLS/UDID 证明才替换凭据并隔离旧凭据。通用 CA renewal 保持关闭，离线跨过到期须人工重新注册。真实 Mac 的 profile 更新与证书生命周期仍需设备验收。

操作、外部 CA 与恢复见 [Apple 指南](../guides/apple-management.md)。参考 [Apple 证书管理](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)、[APNs 响应](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)，协议来源固定于 [Apple fixtures](../../fixtures/apple-tools.lock.json)。
