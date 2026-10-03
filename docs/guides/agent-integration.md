# Agent 注册与报告

服务端接入使用 [agent-wire](../../crates/agent-wire/README.md) 的闭合协议，版本、schema 和能力形态由协议包唯一持有。Agent 实现位于独立仓库；本指南不证明终端采集或执行已验收。

## API 版本与注册授权

注册生命周期为 `/api/agent/enroll/v1`，运行请求为 `/api/agent/runtime/v1`，二者独立演进。运行 JSON 的 `wireVersion: 6`、capability `*.v6` 和任务签名域保持原值；HTTP 版本不驱动载荷升级。[agent-wire](../../crates/agent-wire/README.md) 分别发布 `enroll`、`runtime` schema 清单与指纹。

所有已认证用户可注册自己的设备，默认每用户最多 10 台，未过期的活跃授权预留也计入配额。租户配置可以关闭新用户注册（limit=0），不影响已注册设备。授权默认 24 小时，最多 7 天；数据库只保存租户隔离的秘密摘要。

三种来源统一进入独立 Agent 证书链路：

1. 网页下载：已认证用户调用 `POST /api/v3/agent-grants`，提交稳定 operationId、客户端生成的 32 字节随机 secret、platform，可附 CSR；响应包含 grantId 与原期限。
2. 已安装客户端浏览器授权：客户端调用 `POST /api/agent/enroll/v1/requests`，必须带本机私钥签名的 base64 DER CSR。用户通过 `/api/v3/agent-requests/{id}` 查看公钥指纹，并调用 `/api/v3/agent-grants/{id}/approve` 确认这一请求；会话和 CSRF 检查由浏览器边界持有。
3. 原生 MDM 安装：在原生管理 TLS 监听器调用 `POST /api/agent/enroll/v1/native-grants`，提交 installationOperation、operationId、secret、CSR、runtime profile。服务端验证真实原生客户端证书、当前来源注册、冻结安装/软件/策略授权、已下发事实与原期限，只返回 grant。

持有 grant 的客户端调用 `POST /api/agent/enroll/v1/certificates`，提交 `wireVersion:1`、operationId、grantId、secret、CSR 和 runtime profile。服务端先持久化唯一签发意图，绑定 operation/CSR/SPKI，再请求 CA，并持久化已验证的候选证书链。精确重试返回相同候选；不同 operation、CSR 或 profile 拒绝。签发结果未知时保持同一个 issuanceId，不自动二次签发。

候选还不是活跃设备身份。客户端持本机私钥，在真实 mTLS 下调用 `/api/agent/enroll/v1/activate`，提交 issuanceId 与稳定 operationId。服务端在一个审计事务内复查原授权、期限、来源与证书，并创建独立 DeviceId、Registration、一个活跃凭据及冻结采集定义。CA 信任、原生证书、DeviceId、主机名、HTTP 转发头都不能单独建立 Agent 身份。

`POST /api/agent/enroll/v1/status` 用原 grantId/operationId/secret 查询持久进度；浏览器使用 `/api/v3/agent-grants/{id}`。成功激活回执固定，ACK 丢失后重试原 operation；不能通过换 operation 绕开未知结果。撤销未完成授权使用 `/api/v3/agent-grants/{id}/revoke`。注册后的撤销仍使用 `/api/v3/devices/{device}/registrations/{registration}/revoke`，要求资源级 credentials 权限。

## 同身份换证与未知签发恢复

当前有效 mTLS 设备手动调用 `/api/agent/enroll/v1/renewal-grants`；证书已过期或私钥丢失时，管理员通过 `/api/v3/agent-registrations/{id}/recovery` 创建短期恢复授权。两者复用同一候选签发和持有者激活路径，激活以原凭据为 CAS 前驱，仅替换凭据，保留 DeviceId、registration、generation、epoch、能力、采集定义和执行日志。旧凭据立即成为 retired，不能继续运行或续期。

未知签发由管理员找回 CA 中原始证书链，并通过 `/api/v3/agent-issuances/{id}/recover` 提交。服务端验证原 CSR、公钥、SAN 身份、签发窗口、直接签发者和 provisioner；禁止用重新签发的不同结果替代已保存候选。无法找回结果时不猜测成功，也不自动重签。

## 报告与状态

报告请求使用真实 mTLS；每次请求及业务事务都复查证书有效期与当前凭据状态。注册回执的 `collections` 返回服务端选择的冻结采集定义；报告必须携带对应完整 `collection` 对象，以及 wireVersion、reportId、sequence、observedAt、body。Agent 按 dataset 选择回执中的定义，不能自行增加字段或来源。普通字段值示例：

```json
{"field":"device.model","value":{"kind":"value","value":{"kind":"string","value":"Model A"}}}
```

snapshot、partial、failed 分别表达完整快照、部分结果和失败。空的成功快照与未执行、失败不同。通道状态也使用目录中声明的普通字段；不存在 `mdmEnrollment` 报告特例。字段身份、类型、来源和预算由冻结的定义决定，重复字段、定义外字段和未知 JSON 成员被拒绝。`POST /api/agent/runtime/v1/reports` 在不可变报告、摘要和成功审计提交后返回 202/durable；相同 reportId 与相同语义返回原 receivedAt，不同语义返回 409。

待投递报告达到有界容量时返回 service_unavailable，优先恢复既有 reportId。历史裁剪不得删除 pending 报告。Agent 与 Windows MDM 均由 `collection_runs` 持有不可变报告和最小交付进度，不存在第二套报告队列或 owner 分支。

恢复及 Agent 状态读取共同核对持久报告的 tenant、registration、source、epoch、dataset、reportId、sequence、coverage、规范字节和摘要，并要求报告已封存；数据库关系列与冻结报告内容不一致时拒绝恢复。

后台沿用唯一的 Inventory 运行时：保存不可变完整 CollectionRun 结果，通过有界摘要引用提交 Observation。产品投影验证引用和来源后应用成功字段；部分结果与失败不能清空旧事实，只有完整快照或显式 tombstone 能删除对应来源旧项。`GET /api/agent/runtime/v1/reports/{reportId}` 只允许当前有效 credential 读取当前注册/epoch 内的报告，返回 durable ack、Observation 状态与 Projection 状态。credential 被替换或撤销后，新报告和状态读取立即返回 401；替换前已提交的不可变报告仍可由后台恢复投递。

协议拒绝保留独立错误类别，不返回内部诊断或秘密。当前无已部署旧 Agent 的升级承诺；新注册须使用 V6，见 [运维](../deployment/operations.md)。企业任务签名、领取与启动许可见 [企业任务](enterprise-tasks.md)。

## Agent 上报本机 MDM 状态

具有 `mdm.enrollment.v6` 的 Agent 用 `/reports` 提交注册回执中对应的冻结 `collection`，并以 `body:{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":"unenrolled"}}}]}` 上报普通字段；其它闭合状态为 `this_organization`、`other_organization`、`unknown`。部分采集使用 `partial`，sequence 按该冻结采集定义的来源与 dataset 单调递增。该事实进入现有 CollectionRun、Observation、Inventory，字段为 `channel.mdm.enrollment`。标准入口任务的结果只说明入口是否打开，完成注册须由后续本机观察证明。

## 无兼容退出

旧 `/api/agent/v6` 路由、Agent Bearer 凭据、Agent Enrollment 口令及原生直接注册入口全部退出，不提供别名或认证降级。只支持新部署/重新注册；数据库安装准入仍只接受空库或完整当前账本，没有旧库升级。原生 Windows/Apple 的五分钟 Enrollment 口令及 credential_ref 保留。真实 Agent、安装器、网页消费与真机验收在各自后续任务完成，受控服务端测试不代替这些证据。

## 当前 V6 软件执行上下文与结果

全部 Agent 注册（包括仅库存注册、托管安装注册）以及软件任务请求都必须包含完整 executionContext：递增 revision、OS 数字版本、systemBroker、明确 interactiveUser（没有会话时为 null）、来源范围只读凭据引用，以及 MSIX sideload/unsigned 能力。用户绑定包括精确 SID/UID 与 sessionId；上下文变化须使用更高 revision，旧 Offer 不能启动。每个依赖步骤分别检查 profile、执行上下文和材料；没有通用软件能力兜底。

软件结果是绑定 definitionDigest 的逐步骤证据：index/stepDigest、target、package、native identity、独立 before/after 检测、process、重启及诊断。MSIX 注册与 provisioning 使用不同 identity 变体，错误步骤、用户会话、包身份或作用域拒绝投影。退出码不能代替独立检测；Unknown 保留原任务恢复身份。当前 wire 为 V6，只维护当前软件 shape 与指纹，消费方须更新精确依赖。

V6 删除软件 ownership 和 AppCopy 的 materialSha256，旧字段即使为 null 也拒绝；AppCopy 仍绑定完整 DMG 摘要、明确的包路径和目标名、bundle ID、版本、执行身份与独立前后检测。此变更同时将软件 Resource 的摘要域和持久化标记切到 V4，其它 Resource 格式不变。服务端只支持新部署；独立 Agent #2614 须更新到同一固定契约，当前服务端测试不代表 Agent 或真机已完成。
