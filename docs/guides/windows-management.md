# Windows 原生管理

产品直接终止注册 HTTPS 与管理 mTLS，不接受转发头作为设备身份。先按 [注册指南](device-enrollment.md) 创建 mdm.windows 授权并分发口令。Discovery、Policy、Enrollment.svc 与 MDM.svc 使用配置的精确 origin，Host/To 必须一致；设备须预先信任服务 TLS 根。

## 证书与会话

产品 CA、TLS 私钥和协议保护密钥分别管理；协议密钥不复用 CA/TLS 密钥，并与数据库一起保护和备份。issuer、保护密钥或注册配置身份变化时，按明确恢复/重新注册流程处理，不能把旧注册隐式映射到新配置。

Windows UsernameToken 使用 enrollmentId 与一次性口令。签发期间持续核对原管理员授权，最终绑定提交后证书才可准入。响应丢失沿原意图恢复；重启后由原管理员重新登录、resume。证书安装位置及 Full/Device 注册须在对应 Windows 版本上单独验收，EntDMID 不能替代 mTLS 身份。

管理会话同时校验证书链、用途、当前凭据映射与 SyncML 认证。采用 APPSRV BASIC / CLIENT DIGEST；会话绑定注册世代、证书与消息关联，精确重传返回原响应，异内容冲突。被替代会话不能继续推进。撤销后新准入立即拒绝。Full 用户任务的 `NativeTarget.User.userId` 必须等于当前注册的 `userContextId`，创建、投递和回执都重新核对。会话初始 LoginStatus.User 只表示该已认证会话的用户可用；None、Others 或缺失时用户任务等待，设备任务仍可执行。续期保持注册与用户上下文，重新注册生成新的上下文，旧标识不能沿用。

会话以加密的原始请求和实际响应记录为唯一关联来源，重启后按 MsgID 连续重建；没有另存的关联缓存。当前预算为最多 128 条消息、每条 XML 512 KiB、编码对象 16 MiB、解码对象 12 MiB；响应还受设备声明的 MaxMsgSize / MaxObjSize 限制。非 Final 包仅积累回执，完整 Final 与当前授权共同决定成功结算。

Get Results 的 MoreData / Size 在连续消息中重组，最后一片通过大小、引用与授权核对后才形成值。单 Item Add/Replace 可按实际 XML 字节分片；每片范围留在原 attempt，213 只允许继续传输，最后一片的成功回执才代表对象交付。Atomic/Sequence 保持整体，不跨包拆分。中断、大小冲突及预算耗尽关闭传输并保留未知结果；Abort 和非 Final 预算耗尽将未完成采集分别以 aborted / message_budget 失败结束，不投递成功快照，沿既有恢复 owner 处理，不盲目重发有副作用的命令。

1226 Generic Alert 保存原生类型、源 URI 和不可逆证据摘要并原样关联 ACK；1222 / 1223 / 1225 仅控制协议传输。通知与交付回执不证明业务效果，也不提供应用 Correlator 支持。

真实 TCP peer 承担连接/速率限制，NAT 后设备可能共享预算；接入拒绝不放大数据库审计。过期临时会话可清理，凭据、签发与审计事实仍保留。协议字段及预算由 [codec](../../crates/windows-mdm/src) 与 [Windows 通道](../../crates/windows-channel/src) 持有；原始样本来源见 [fixtures](../../crates/windows-mdm/tests/fixtures/README.md)。

## 用户任务与配置输入

有权管理员先从 `GET /api/v3/devices/{device}/registrations` 的 Full 活动注册读取 `userContextId`，使用[设备操作](device-operations.md#windows-原生操作)现有 `/api/v3/devices/{device}/operations` 入口。以下命令生成可提交 JSON；`user_context_id` 必须替换为该注册返回的值，提交仍需既有会话、Origin/CSRF 和设备操作授权：

```sh
user_context_id='<当前 Full 注册的 userContextId>'
jq -n --arg operationId "$(uuidgen)" --arg userId "$user_context_id" --argjson deadline "$(($(date +%s)+300))" '{operationId:$operationId,inputVersion:"user-input-v1",deadline:$deadline,target:{kind:"user",userId:$userId},task:{platform:"windows",request:{kind:"sync_ml",request:{kind:"node",node:"./User/Vendor/MSFT/Policy/Config/Experience/AllowThirdPartySuggestionsInWindowsSpotlight",instance:[],operation:"get",value:null}}}}'
```

用户配置内容沿同一 Resource 上传与 Policy 消费路径，`apply` / `remove` 属于当前注册的用户 scope。配置 JSON 的形状如下；将 userId 替换为上述值，资源版本提供 operation 的 inputVersion：

```json
{"target":{"kind":"user","userId":"<当前 Full 注册的 userContextId>"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./User/Vendor/MSFT/Policy/Config/Experience/AllowThirdPartySuggestionsInWindowsSpotlight","instance":[],"operation":"replace","value":{"type":"integer","value":"1"}}}},"remove":null}
```

## 通道配置与维护

`windows.poll` 是必填的八字段配置，分钟单位；完整示例见 [配置样本](../../fixtures/mdm-config.example.json)。样本先每 15 分钟尝试 10 次，禁用第二阶段，然后每天无限轮询；两项登录触发均为 false。配置必须有可到达的无限阶段，不能依赖 Windows 对无效配置的自动修正。注册 provisioning 与后续维护使用同一个类型；维护通过既有 native execution 创建完整 Poll Replace Sequence，部分写入、删除和类型错误被拒绝，并沿既有 readback 确认效果。Rust 消费者调用 `rss_mdm_windows_mdm::native::Request::poll_schedule(provider_id, &poll)`，返回可序列化的完整 Sequence；将其放入已有 `task.platform="windows"` / `request.kind="sync_ml"` 的 operation envelope，target 为 Device，显式提供 operationId、inputVersion 和 deadline。普通 JSON 消费者可用 `serde_json::to_value` 的输出，不能只生成部分 Poll 节点。

WNS 可选。配置 `push.package_family_name`、`sid` 和受保护的 `client_secret_file`；通道向当前已认证设备读取并关联 PFN / ChannelURI。只接受配置 PFN 与 HTTPS notify.windows.com 路由，不跟随重定向。URL 加密保存，token 仅内存缓存。worker 在审计事务内按当前注册世代、来源、凭据及任务授权获取租约，提交后发送空的 wns/raw 唤醒，再按世代、路由版本和租约结算。Accepted 仅为 WNS 接收，Unknown 表示网络结果不确定，两者均不能证明设备签入、命令交付或效果；Poll 独立继续工作。重复观察同一 URL 只刷新有效期，不重置租约或终止结果，URL 改变才增加版本。

DMClient 维护限定当前 provider。DMAcc 先读取所选 account 的 ServerID，证实当前 provider 后才执行账户操作。管理地址修改只能指向配置的主地址或 `additional_management` 中真实启用的独立监听地址；Host、绝对 HTTP URI authority 与 SyncML Target 必须对应实际 listener。效果需另一个会话连接到所需实际地址，并提供关联 readback，客户端自报 Source 不能替代重连证据。

## 续期与原生注销

续期在 Enrollment.svc 上使用原 TLS 叶证书、签名 CMS PKCS#7 与新 CSR。只接受当前证书对应的当前注册及允许的续期窗口；响应可沿原材料精确恢复。签发新证书后旧凭据仍有效，直到新证书首次通过管理 mTLS 证明持有，才在事务内激活新凭据、替代旧凭据。续期不创建新设备、注册或协议账户。

原生 `com.microsoft:mdm.unenrollment.userrequest` 在原事务内退休注册、凭据、执行参与方、采集、push 与活动会话，并保存独立加密回执。并发或丢失响应重试得到相同字节；回执不依赖临时会话保留。退休证书只能恢复这份精确历史请求的回执，不能构造 active principal 或继续接收新工作。服务器退休不能证明终端已清理管理账户，审计中的设备清理状态保持 unverified。

普通 Full 用户注册不依赖组织联合身份。需要外部组织 / parent-linked enrollment 的原生能力继续明确返回 Unsupported；该契约由 #2592 的对应切片与 #2597 承接，不能从普通用户注册推导成功。

## 采集与恢复

CollectionRun 拥有命令关联、完整性与报告封存。Status 或 Final 单独不能证明完成；成功 Status 加关联 Results 才提供字段事实。明确 501 可表明 Unsupported，404/500、超时、缺失不能推断为不支持。所有字段成功或明确不支持才形成完整 Snapshot；Partial/Failed 保留最后完整资产，无字段结果不伪造 Observation。

报告使用稳定 sequence/batch/scope，接收时间用于来源证据。提交未知沿原身份恢复，不能因查询暂时缺失而删除旧资产。报告 durable 与资产投影分别查询；后台故障拒绝健康声明。统一资产不要求调用者选择来源，详见 [资产指南](assets.md)。

配置与升级见 [安装](../deployment/installation.md) 和 [运维](../deployment/operations.md)。受控 TLS/SyncML 测试仅证明服务端接缝；真实设备支持矩阵与证书安装、首次签入和采集闭环须由产品 T3 给出。

协议依据：[DMClient CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/dmclient-csp)、[Microsoft OMA DM](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support)、[w7 APPLICATION CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/w7-application-csp)、[RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.html#section-5)。
