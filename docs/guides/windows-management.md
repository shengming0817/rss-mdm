# Windows 原生管理

产品直接终止注册 HTTPS 与管理 mTLS，不接受转发头作为设备身份。先按 [注册指南](device-enrollment.md) 创建 mdm.windows 授权并分发口令。Discovery、Policy、Enrollment.svc 与 MDM.svc 使用配置的精确 origin，Host/To 必须一致；设备须预先信任服务 TLS 根。

## 证书与会话

产品 CA、TLS 私钥和协议保护密钥分别管理；协议密钥不复用 CA/TLS 密钥，并与数据库一起保护和备份。issuer、保护密钥或注册配置身份变化时，按明确恢复/重新注册流程处理，不能把旧注册隐式映射到新配置。

Windows UsernameToken 使用 enrollmentId 与一次性口令。签发期间持续核对原管理员授权，最终绑定提交后证书才可准入。响应丢失沿原意图恢复；重启后由原管理员重新登录、resume。证书安装位置及 Full/Device 注册须在对应 Windows 版本上单独验收，EntDMID 不能替代 mTLS 身份。

管理会话同时校验证书链、用途、当前凭据映射与 SyncML 认证。采用 APPSRV BASIC / CLIENT DIGEST；会话绑定注册世代、证书与消息关联，精确重传返回原响应，异内容冲突。被替代会话不能继续推进。撤销后新准入立即拒绝。

真实 TCP peer 承担连接/速率限制，NAT 后设备可能共享预算；接入拒绝不放大数据库审计。过期临时会话可清理，凭据、签发与审计事实仍保留。协议字段及预算由 [codec](../../crates/windows-mdm/src) 与 [应用](../../crates/app/src) 持有；原始样本来源见 [fixtures](../../crates/windows-mdm/tests/fixtures/README.md)。

## 采集与恢复

CollectionRun 拥有命令关联、完整性与报告封存。Status 或 Final 单独不能证明完成；成功 Status 加关联 Results 才提供字段事实。明确 501 可表明 Unsupported，404/500、超时、缺失不能推断为不支持。所有字段成功或明确不支持才形成完整 Snapshot；Partial/Failed 保留最后完整资产，无字段结果不伪造 Observation。

报告使用稳定 sequence/batch/scope，接收时间用于来源证据。提交未知沿原身份恢复，不能因查询暂时缺失而删除旧资产。报告 durable 与资产投影分别查询；后台故障拒绝健康声明。统一资产不要求调用者选择来源，详见 [资产指南](assets.md)。

配置与升级见 [安装](../deployment/installation.md) 和 [运维](../deployment/operations.md)。受控 TLS/SyncML 测试仅证明服务端接缝；真实设备支持矩阵与证书安装、首次签入和采集闭环须由产品 T3 给出。

协议依据：[Microsoft OMA DM](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support)、[w7 APPLICATION CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/w7-application-csp)、[RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.html#section-5)。
