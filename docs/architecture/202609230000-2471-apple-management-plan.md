# #2471 Apple 手动注册、资产与 Profile 管理实施计划

本次复核按“彻底、不向后兼容、优雅简洁”收敛：所有产品实现使用 Rust；step-ca v0.30.2 只负责外部 SCEP 签发；NanoMDM 只作隔离 T2 协议对照，不持有产品身份、队列或结果。

## 实施顺序与文件归属

主 agent 负责全部实施文件，按 A → B → C → D 串行推进；探索与最终 review 可按 ship 技能并行，实施不交叉写文件。

| 批次 | 主要文件 | 验收 |
| --- | --- | --- |
| A 来源、装配与迁移 | inventory/source、app/enrollment、device、config、native、migration | 注册必须声明 source；Apple-only 无 Windows 配置；只追加一个迁移单元；旧在途工作未排空则拒绝升级 |
| B Apple 身份与协议 | app/apple | 有界 plist；独立 CMS 验签；SCEP 单次消费、签名回调、固定签名主题、公钥与签发尝试绑定；mTLS、Authenticate、TokenUpdate、CheckOut、代际隔离 |
| C 操作与采集 | app/commands、collection、inventory_runtime、api、authorization | Profile 共用 Commands/outbox/reconcile；设备信息共用 CollectionRun；APNs 无命令推进权；关联 ACK 与完整 ProfileList 分层 |
| D 交付与证据 | hack、fixtures、测试、指南、CI | 真实 PG 与固定 step-ca，HTTP/2 APNs 受控端、隔离 Nano 对照；Windows 回归；PR 内置 review 与 ship 交接 |

## 新契约

- 注册生命周期整组使用 `/api/v3`。请求及注册来源为 `agent.builtin`、`mdm.windows`、`mdm.apple`；`channel` 保留为内部设备通道维度，不再推断注册协议。
- 配置必须有闭合的 `native_protocols`；成员 `windows`、`apple` 的存在表示启用，空对象为 Agent-only。删除顶层 Windows 解析。
- Commands 整组使用 `/api/v2`，包括计划执行；dispatch 唯一版本 `mdm.command-dispatch/v2`，route `device.command`，消息与 reconcile 域 `mdm.commands.v2`。不保留旧路由、别名或运行时 decoder。
- `POST /api/v1/devices/{id}/collection-runs` 接受 `source=mdm.apple` 和 `requestId`，返回 202、`runId`、`pending`；使用设备级 `inventory_collect` 权限。服务端冻结 registration、generation、epoch、coverage、approval、deadline。
- 安装任务 `profile_install` 仅接受 EnableFirewall；移除任务 `profile_remove` 必须指向当前产品拥有的 PayloadUUID。Identifier 稳定绑定 tenant/device；每个安装 operation UUID 是不可变 Profile UUID。同一配置的写操作串行。

## 证据与生命周期

内部 outbox 发布成功才是 Published；APNs 200 只表示唤醒被接受；关联安装 ACK 是 Received；NotNow 保持待执行；原生错误为 Rejected；完整、认证并关联的 ProfileList 才能得到 Applied。预期摘要绑定 identifier、UUID、期望存在性。状态只证明 Profile 存在性，不宣称操作系统防火墙已经生效。

DeviceInformation 不进入 device-command。固定采集 Model、OSVersion；有效结果封存后经 Observation 投影至 Inventory。Partial/Failed 按既有 Observation 契约保留最后完整资产，最新字段质量由 CollectionRun 呈现；不合并成伪造 Snapshot，不引入字段 TTL。没有本次报告时，超时只记录采集失败事实。

SCEP challenge 的授权消费先提交，再返回 allow；同事务、同 CSR 的重复回调也不得再次允许。CA 模板必须从签名 webhook 的 `.Webhooks.rss.subject` 设置 `CN=<enrollment 的 32 位小写 hex><attempt 的 32 位小写 hex>`（64 字符；真实 CSR 测试证明带连字符和分隔符的初案超过 CN 上限）；不得信任 CSR 提供的任意主题。叶证书严格校验专用 issuer、主题、EKU、有效期、公钥、serial/fingerprint。通知丢失可由首次匹配的有效 mTLS 证书恢复；签发响应丢失需新授权，不透明重签。

设备注册先 pending_token，再由首个 TokenUpdate 激活。仅支持设备通道；UserAuthenticate 返回 410。MDM payload 包含 per-user-connections capability，但不提供用户管理。SignMessage=false，传输安全由 HTTPS/mTLS 提供；AccessRights=19、CheckOutWhenRemoved=true，生产 APNs。

## 迁移与验证约束

安装账本 39 → 40，仅支持当前版本和紧邻前版。升级前必须排空旧非终态命令、未发布 outbox、有效管理会话、未封存或未投递 collection、旧 reconcile 工作与租约。已有 SQL 不改写；历史结果、审计、已发布 outbox 保留。新幂等摘要域拒绝旧 key，不解码旧 receipt 来兼容重放。

按批次先建立失败用例，再跑最小回归。最终 `make ci CI_BASE=origin/develop` 按 ship 在清洁提交与 label 后执行一次，失败项精确复验。真实 Apple 组织与 Mac 的 T3 在 #2482，本次受控 T2 不替代真实设备验收。

## 实施证据与剩余交付

- 注册 source、闭合 native_protocols、Apple plist/profile/webhook/摘要与采集质量测试完成红→绿。
- 真实 PostgreSQL：上一版排空升级、全新安装、重复安装、不可变摘要、损坏账本拒绝和并发安装串行验证通过；最小角色与 catalog 快照由隔离迁移数据库核验。
- 固定 step-ca 的真实 SCEP、CMS 独立验签、mTLS、采集和 Profile 生命周期通过；新增通知丢失恢复、重复 SCEP 拒绝、错误关联、NotNow、原生错误、Profile mismatch、token revision 与 CheckOut 测试通过。
- HTTP/2 APNs 受控端验证实际客户端证书、请求头和 JSON，覆盖 200/410/429/503/400；APNs 回执不能推进 Commands。
- 固定 NanoMDM 使用独立 filekv 接收相同设备 PDUs，对比实际下发命令字段，不持有产品状态或调用生产 APNs。
- Windows 原生命令完整 T2 已通过。
- 真实联调修正：两个 UUID 的 CN 编码为 64 小写 hex；按 CN 内容接受 UTF8String/PrintableString；step-ca 通知类型为 NOTIFYING，两个独立 HMAC 身份；webhook TLS 信任不来自 federatedRoots；启用首个 SCEP provisioner 后重启 CA。
- ProfileList 使用完整列表而非 ManagedOnly，不依赖尚未验证的 macOS 版本；Partial/Failed 沿用最后完整资产的既有权威规则。

重注册、活跃公钥复用拒绝、授权撤销阻断原生命令/APNs、未报告采集超时均通过真实 T2；独立 target 下 T1（59 项）与全 target/all-features Clippy 通过。后续完成容量 gate、PR 内置 review、完整本地 CI 与 ship 交接。一次共享 target 构建读到其他 worktree 的 CollectedValue::Scalar，已切换本任务独立 target；失败构建不计作验证通过。最终结果以绑定提交的 CI 和 PR artifact 为准。
