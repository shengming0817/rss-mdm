# 设备操作与原生配置

## 范围与接口

`POST /api/v1/devices/{device}/operations` 只接受 `operationId`、Unix 秒 `deadline` 和闭合 `action`。不接受 task、inputVersion、target、platform、URI/CSP、脚本、配置、软件、诊断或附加原生参数，也没有旧合同兼容入口。

| 动作 | action 参数 | 权限 |
|---|---|---|
| restart | `{"kind":"restart"}` | device_control |
| lock | kind、confirmed:true、expectedRegistrationId、expectedGeneration、六位 ASCII 数字 pin | device_control |
| wipe | kind、confirmed:true、expectedRegistrationId、expectedGeneration | device_wipe |

危险动作的确认绑定当前主 MDM 注册世代，错代次返回冲突。`GET /api/v1/devices/{device}` 的 nullable `primaryMdmRegistration` 返回 registrationId、generation、source；不能从 channels 中的声明式或用户注册推断主注册。

| 平台前提 | restart | lock | wipe |
|---|---|---|---|
| Windows 当前主 MDM；已核实 build/edition | 固定 RebootNow | Unsupported | 固定 RemoteWipe/doWipe |
| macOS Device enrollment；已核实 OS 与硬件 | >=10.13 | Intel >=10.8；Apple silicon >=11.5；必须已知硬件 | Apple silicon >=12.0.1；DoNotObliterate；不允许 obliteration 回退 |

Intel/T2 状态未知或不满足条件时不开放 Mac 擦除。平台事实必须来自同一注册世代的已认证原生交换，不能由管理请求提供；未知前提拒绝创建。该矩阵仍受固定平台 schema 与 enrollment access rights 约束，协议测试不替代真机验收。

创建返回 202 和稳定 operation/command 身份；同请求 UUID、主体与内容重放原回执，异内容返回 409。PIN 进入现有加密原生输入，不出现在授权 JSON、查询、审计或 Debug 中。

读取使用 `GET /operations/{id}`（operation_read）。取消使用 `POST /operations/{id}/cancel`，正文 requestId、expectedRevision（operation_cancel）。重新授权使用 `POST /operations/{id}/reauthorize`，正文 requestId、expectedRevision；lock/wipe 另须 `confirmation:{confirmed:true,expectedRegistrationId,expectedGeneration}`。重新授权只刷新原动作权限，不修改动作、PIN、注册或 deadline。Policy 子命令由其 owner 取消，不接受此设备取消入口。

## 结果与恢复

queued 是持久受理，published 是 Outbox 网关接纳，received 是关联原生回执。restart/lock/wipe 的 ACK 不证明终端效果，不转成已核实效果或合规。已派发未知变更不自动重发；取消、deadline、撤权和注册替换阻止后续执行，不表示副作用回滚。

503 operation_unknown 表示提交可能完成：保留原请求和 UUID，先查询并以原内容重试；404 不能证明回滚。命令、Outbox、回执和审计继续共用原事务及现有 reconcile/device-command 恢复设施，重启不产生替代 operation。

Remote 与旧通用直接命令无部署升级义务，已完整退出。当前安装 schema 不接受旧安装账本；不提供历史执行导入或兼容查询。

`GET /api/v1/operations` 使用 `filter/sort/fields/limit/cursor`，返回 `items/nextCursor`；设备、Policy、状态条件写入 filter，排序以 `(id,kind)` 保证复合身份唯一，cursor 为签名的不透明值。精确统计单独请求 `/api/v1/operations/statistics`，使用相同 filter 并返回观察时刻。摘要移除原始输出与诊断流，完整证据沿 detailUrl 检查当前设备范围权限。仅选择 id/kind 等元数据时不读取大型执行证据；证据按选中页批量补齐。执行事实及证据变化使目录游标失效，无变化的恢复不推进世代，事务回滚不留下已提交世代。脚本、原生采集、配置和软件继续走各自 Policy owner，见[企业任务](enterprise-tasks.md)。

命令连接 execution.database 使用 mdm_command_runtime。完整运行配置见 fixtures/mdm-config.example.json；恢复和安装要求见[运维](../deployment/operations.md)。

## Windows 原生操作

Windows 使用固定 DDF/CSP/ADMX 来源和 Node/Atomic/Sequence 类型化操作树，通过现有 Resource/Policy/Scope 和受保护执行路径管理对象。动态身份、设备/用户 scope、build/edition 和实际操作权限分别校验；客户端不提供可信平台或权限事实。

Resource 元数据入口为 `/api/v1/resources/{id}`，配置内容通过既有 `/api/v1/resources/{id}/content` 上传并保护。Policy 与设备动作使用 `/api/v1`；配置内容示例：

```json
{"target":{"kind":"device"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana","instance":[],"operation":"replace","value":{"type":"integer","value":"1"}}}},"remove":null}
```

Policy 引用精确资源版本/variant；它消费完整操作权限和多对象 claims。软件原生 MSI 输入保持通用，但产品安装准入只允许既有固定 Agent。安全 Policy、证书及凭据载体要求对应 SecurityOperate/Credentials，不能以 configuration_write 或 inventory_collect 绕过。

查询分别返回原生 receipts、执行进度、effect 和 effectReason。ACK 不证明效果；效果为 verified、diverged、waiting 或 unverifiable。DomainProfile/EnableFirewall 仍只有原生 Replace，DeviceStatus 的设备整体状态不能证明该叶效果。Policy Delete 可能恢复默认值；缺少固定检测条件时保留 unverifiable 和 guards，超时/取消不重发已派发未知变更。

机器来源、逐文件摘要和归档摘要分别固定；生成/更新命令见[本地开发](local-development.md)。原始请求、回执和关联绑定租户、设备、注册世代及操作身份并加密保存。用户/linked 身份维护、持续配置与会话增强由对应生命周期 owner 提供；必要前提缺失只拒绝相关操作。受控协议验证不代表真机效果或合规。

安装、升级和后台诊断见[运维](../deployment/operations.md)。ActionRun 与状态型任务分离，脚本退出码不转成变更效果；见[企业任务](enterprise-tasks.md)。


## 设备时间线

管理员通过 `GET /api/v1/devices/{device}/timeline` 检索现有注册、凭据、资产和管理审计事实，可用 `operationId` 和时间区间筛选。入口复用现有管理读取能力；不需要额外申请时间线权限。时间线只呈现已经持久化的事实，受理、请求结算、执行状态和实际效果分别解释；缺失结果保持未知，202 不表示设备执行成功。

时间线和管理审计检索都在授权成功后按需增量追赶，无访问时不扫描。每次读取有界推进；长期积压可能需要重新查询。临时故障返回不可用，后续授权查询重新尝试。

排序使用持久记录时间，发生时间另行显示。分页使用响应中的签名游标和相同筛选条件；第一页固定上界，新事实需要重新查询。响应的覆盖进度说明索引追赶情况，未完成追赶不表示设备没有历史事件。字段、筛选和预算的唯一契约见 [timeline-service](../../crates/timeline-service/src/model.rs)。

未保存可信设备关联的历史事实不推测归属，仍可从管理审计入口按 operation 查阅。覆盖进度只说明源记录索引进度，不证明设备生命周期或所有业务阶段齐全。

## 跨通道设备视图

`GET /api/v1/device-views` 在服务端按当前可见关联归并，使用统一 `filter/sort/fields/limit/cursor`。`filter` 可组合 search/platform/status/channel/source/assetState，例如 `filter=search=icontains=mac;platform==macos`；完整条件须由同一成员满足，筛选和完整关联在截页前完成。列表返回 `items/nextCursor`；`GET /api/v1/device-views/statistics` 仅接受同一 `filter`，独立返回 endpointCount、deviceViewCount 和观察时刻 asOf。候选预算为目录 4096 个可见端点、统计 16384 个，原始来源预算分别为 1,048,576 / 4,194,304 行，在历史请求去重和字段值解码前检查；超限明确失败，不返回截断结果。详情使用 `/api/v1/device-views/endpoint/{device}` 或 `/api/v1/device-views/association/{id}`；原 `/devices` 继续表达注册端点。主通道的 children 展示当前父注册下各 purpose 的最新子注册，保留父子注册、代次、生命周期和 ready；撤销子注册不替换或撤销主通道。Windows Full 的 userContext 保留原生用户上下文及其父注册状态，不表示用户在线或动作可执行。仅看见一个成员时返回普通端点，不披露关联、另一成员或其数量。

后台按当前已认证采集来源的序列号或硬件 UUID 自动关联同租户的 MDM、Agent 主注册。值须有效、匹配、无其他有效字段矛盾且在当前实例中唯一；大小写与外围空白归一，序列号前导零和标点保留。占位值、主机名、MAC、登录用户和 Manual 赋值不参与自动确认。已关联的两个端点算一个实例。新注册代际有相同证据时自动延续；暂未上报时保留成员和历史，后续上报重新判断。重复、冲突或失效的注册显示 needs_verification。

异常通过 `GET /devices/{device}/association-candidates?channel=mdm|agent` 选定当前主通道，使用 `POST /device-associations` 明确确认。请求携带 operationId、associationId（新建为 null）、expectedVersion、mdm/agent 的 device、channel、registrationId、generation，以及核实记录 evidence。两个端点均须有当前 inventory_read 和 device_association_write。撤销用 `POST /device-associations/{id}/revoke`，携带 operationId、expectedVersion 和 reason；成员立即释放，同一对端点不会自动合回，显式确认可恢复。重试保持相同 operationId 和请求内容。变化历史从 `GET /device-associations/changes` 读取原审计事实。`nextCursor` 继续当前固定上界的分页，末页返回 `checkpoint`；后续将 checkpoint 作为 cursor 参数传回，即从已扫描位置读取新变化，空页也保留 checkpoint。两者均绑定租户、用户与实时权限；权限变化后须重新查询。每条可见变化的 position 用于消费去重。

目录和详情的 endpoints 共用 displayName、serialNumber、platform、registrationUser 和 currentUser 投影。名称按 Windows device.name、Apple HostName/LocalHostName 的现有字段来源选择，序列号复用 Inventory 解析；未采集和来源冲突保留实际状态。platform 使用注册来源及 Agent 注册平台，未知或冲突不猜测。search 对可读取的名称、序列号及两类后端人员 principalId 执行去首尾空白、忽略大小写的字面子串匹配，最多 256 UTF-8 字节，空白查询和控制字符拒绝；姓名搜索匹配所有可展示且有效的 Identity 来源，本地 login 独立匹配；资料 username 单独标注，不冒充 login。多个过滤条件在同一可见端点命中，关联设备只计一次视图，端点数量单独计数。

registrationUser 沿用 enrollment 读取权限，currentUser 要求现有租户级 inventory_sensitive_read 许可，且目标端点已通过 inventory_read 授权；敏感许可与设备可见范围取交集，不扩大设备范围，也不提供逐设备单独授予敏感读取的能力。Inventory 标量遵循字段敏感性与同一授权交集。无权字段不返回，也不参与搜索、计数或目录游标绑定。目录游标只携带认证的上下文摘要和位置，绑定当前主体、查询、权限和可见投影；相关领域版本变化使游标失效，包括无法单独归因到当前可见集合的变化。详情仍保留逐端点所有人，关联不会创建或批量覆盖第二份人员关系。关系中的 display 是必需展示字段；未绑定或无权展示时为 null。有原关系读取权限且具备 inventory_sensitive_read 时，人员资料按既有 user_profiles_read（本人沿用原例外）读取，本地 login 按 identity_accounts_manage 读取；API Key 不获得自然人资料上下文。仅有效来源返回姓名/username，过期或不可用来源保留无值状态。修改本地资料后，最新登录观察在该人员再次登录后更新；账户停用和来源撤销使其资料不可用。展示和搜索复用同一请求内投影，人员来源版本变化使续页失效。

字段沿用原有字段优先级策略，各端点的 Manual 值独立保留，同优先级不同值为 Conflict。列表显示每个端点来源的状态、证据及 cursor；以详情返回的来源 cursor 调用 `GET /device-views/{kind}/{id}/inventory-lists/{field}?cursor=...&limit=...`。分页不对不同来源的列表做集合拼接，采集完整性和失败信息保留在 inventorySources。游标签名绑定用户、权限和查询快照；响应 `device_view_cursor_invalidated` 时从第一页重新查询。

重新授权由当前具备原动作权限的操作者执行，不需要第二位审批人。lock/wipe 的危险动作确认不产生额外权限。当前接口使用 `/reauthorize`、授权状态 `authorized` 和 `authorization_withdrawn`；旧 `/approve` 路由与旧状态编码已移除，调用方须同步切换。

## 恢复凭据

恢复凭据按租户、设备、注册世代和材料对象独立托管。BitLocker 使用稳定卷 ID 与 protector ID，本地管理员密码使用 SID；FileVault PRK、Recovery Lock 和锁定 PIN 保留各自语义。普通资产和操作结果不包含秘密，Bootstrap Token 继续由 Apple check-in 唯一持有，不提供人工明文查询。

`GET /api/v1/devices/{device}/recovery-credentials` 返回版本元数据，使用现有设备读取权限；最多返回 100 项，通过末项的 `id/version` 作为 `afterId/afterVersion` 继续。`escrowed`、`validity`、`current` 分别表示材料是否存在、核实情况和是否为当前已核实版本。轮换后未核实的材料不会覆盖当前版本；Unknown 不表示旧密码仍然有效。

`GET /api/v1/devices/{device}/recovery-credentials/{id}/versions/{version}/secret` 直接返回对应材料，只要求有效登录和该设备的 `credentials` 权限。没有额外 MFA、近期认证时限、原因填写、解锁票据或审批。响应禁止缓存，审计结算失败不返回秘密。撤销使用同一路径前缀下的 `POST .../revoke`，账户材料使用 `account_write`，锁定 PIN 使用 `device_control`，其余材料使用 `security_operate`。撤销托管访问不等于删除端上的密码或 protector。

Apple 操作入口为 `POST /api/v1/devices/{device}/recovery-credentials/operations`，携带 `operationId`、`registration`、`generation`、Unix 秒 `deadline` 和类型化 `action`。FileVault 原生命令只针对启动卷，不接受调用方指定任意卷。可配置 FileVault escrow、采集或轮换 PRK、重新核对已有 PRK 候选、设置/清除及验证 Recovery Lock。轮换 PRK 的 `unlockPassword` 只用于官方原生命令；缺少平台前提不自动改走脚本。`reconcile_filevault` 和 `verify_recovery_lock` 引用已有 `material: {id,version}`，核实 Unknown，不重新生成秘密。Recovery Lock 候选未生效时，在原设置操作结束后使用 `reconcile_recovery_lock`，提供原 `operation` 与待核实的 `material`；只有平台确认密码有效才结束未决候选，单次验证 false 不解除保护。FileVault 采集可指定已配置的历史 `recipient` 指纹。

macOS 锁定继续使用原 `lock` 动作，其 PIN 同事务进入托管。部署需先配置恢复凭据密钥和接收证书。原生 ACK、已托管、平台核实与实际恢复效果分别记录；真实 Windows/macOS 恢复效果由独立产品 T3 提供证据。

Agent 核实策略会绑定同一注册世代中匹配的 Unknown 轮换 task/attempt。Agent 必须先停止原操作的本地执行，再从受保护 journal 核实“原状态未变”或“新材料已生效”，将密文与核实结果持久回传；没有收到任何材料的原操作也可恢复。若受保护日志证明原操作尚未发起 OS 变更且已停止，返回 `not_attempted`，原操作按未执行成功结算；不会要求读取未知旧密码，也不宣称密码已核实或 OS 已回滚。核实完成前不会解除轮换保护，取消不表示 OS 变更已回滚。


## Webhook 对外事件

管理员在 `/api/v1/webhooks/subscriptions` 查询订阅，通过
`PUT /api/v1/webhooks/subscriptions/{id}` 创建或修改。写请求使用
`{"operationId":"<UUID>","expectedRevision":0,"change":{"kind":"put","value":{...}}}`；
启停用 `change: {"kind":"enabled","value":true|false}`，删除用 `change: {"kind":"delete"}`。
新建默认停用；后续操作使用返回的 revision。Settings 包含 name、endpoint、eventTypes、
selection、keyReference、networkReference。selection 使用 `allDevices`、`devices`（ids）或
`groups`（ids）；组必须是当前已发布的 endpoint 成员集合。事件目录见
`GET /api/v1/webhooks/event-types`，精确 V1 载荷见
[事件 schema](../../crates/webhook-service/schema/event-v1.json)。仅输出登记、退役、策略执行终态、
已发布合规结论变化；Unknown 不推断为执行成功。

`WebhookRead` 允许配置及投递查询；`WebhookWrite` 允许配置、启停和测试；
`WebhookReplay` 允许恢复。它们不替代对应设备的 InventoryRead、OperationRead 或 ComplianceRead。
首次 fanout 保存接收订阅版本及组筛选结果，分页恢复沿用该名单；订阅属于租户；发送时检查租户、启停状态及目标版本，不重新筛选组成员，也不复核创建者个人权限。
创建、修改和恢复时检查当前操作者权限；创建者离职或撤权不自动停用租户集成。
设备/组范围更新或目标、密钥引用变化会退休旧 TargetVersion；名称修改只增加 revision。
停用不撤回在途请求，重新启用不恢复旧版本。新订阅不回补启用前的事件。

`POST /api/v1/webhooks/subscriptions/{id}/test` 使用 `{operationId,deviceId}`，走正式授权与 HTTPS。
`GET /api/v1/webhooks/deliveries` 返回分页投递及 nextCursor（作为下一次 after），详情地址为
`/deliveries/{id}`。status 来自 RSS 持久状态，transportObservation 只是接收/未知/未发送观察；
attempts 计发布调用，包含发送前准入拒绝。HTTP 2xx 只证明接收，不证明下游业务成功。
每个目标有独立 MessageId；自动重试保持 ID 和精确 body，接收方应按投递 ID 或业务 eventId 去重。

`POST /deliveries/{id}/redrive` 使用 `{operationId,expectedVersion}`，expectedVersion 取查询返回的
recoveryVersion，必须仍处于原自动投递窗口；`POST /deliveries/{id}/replay` 使用 `{operationId}`，
对失败投递创建新身份并关联原投递，保持原 eventId、body 和 TargetVersion。
退休或停用的版本拒绝恢复，不自动改投新 URL。重试未知提交时复用原 operationId。
`GET /api/v1/webhooks/health` 提供源/目标 Outbox 的规范状态计数，需要 WebhookRead；
源 fanout 死信同样可见，不将无目标记录解释为发送成功。


## Device Access 管理

`GET /api/v1/devices/{device}/device-access` 使用统一 `filter/sort/fields/limit/cursor`，返回 `items/nextCursor`；`GET /devices/{device}/device-access/bindings/{id}` 读取单条绑定。企业配置目录 `/device-access/enterprise/configuration` 使用同一查询语法，但独立字段目录为 `id/kind/value`，详情为 `/configuration/{id}`。恢复凭据 `/devices/{device}/recovery-credentials` 同样返回元数据分页，秘密仍只通过专用授权披露操作取得。三类游标签名绑定资源、租户、主体、权限、设备（设备级资源）和数据版本；查询、权限或源数据变化后重新开始，不接受旧 `after/afterId/afterVersion` 参数。
`PUT /api/v1/devices/{device}/device-access/bindings/{id}` 使用 operationId、expectedRevision 和
`put`/`unbind`/`reset_factors` 动作；新绑定 revision 为 0。Put 指定同一 Identity 实例的 principal、已分配 policy，
以及 existing 稳定账号或 create 平台/账号名。已有绑定换本地目标须新增绑定，不根据名称接管。
后续变更和读取要求当前设备 AccountWrite 权限；只持有本机管理员权限不能调用。
写入前向 `/device-access/bindings/{id}/step-up` POST 同一业务正文，完成 Identity WebAuthn authenticate 后携带用途绑定的 operation cookie 写入。证明先于产品锁消费，并与绑定、回执和审计同事务结算。业务摘要不包含 proof handle；成功后精确重试先返回同操作者的原回执，不额外消费证明。摘要不符返回冲突。
响应丢失先读取 `/device-access/operations/{operationId}`，或精确重放原写入。回执保留当次提交快照，最新设备效果另读绑定列表。

`unbind` 必须明确 `disposition: keep|disable|standard`；通常选择 keep 保留账号状态，禁用和降权由管理员显式选择。三种处置均不删除账号或数据。任务摘要绑定该意图，只有一致的原生回读结果才推进 appliedRevision。

Policy action `device_access` 持有 selfEnrollment、可选 role（standard/administrator）、mac 登录配置与 Windows 机制配置（`windows.kind=disabled|rss_factor|whfb`）；沿用 Scope 分配、
排除和 Policy 启停。role 为 null 时保留已有账号权限，新账号默认 standard。
`rss_factor` 必须提供非空 `accounts` 来源集合（local/active_directory/entra）；`whfb` 固定纯 Entra joined、TPM 2.0 与 PIN，不能配置本地/AD 账号或创建目录账号。变更机制先完成原绑定退役，再建立新绑定；不自动迁移凭据。
serverState、receivedRevision、appliedRevision、effect 各自表达不同事实。
普通配置和角色更新只增加 revision；重新关联人员增加绑定代际及因子世代，Windows 的 `reset_factors` 显式增加因子世代。
撤销立即停止服务端授权；离线本机保持原效果直到实际执行清理，不将接口成功视为即时端侧撤销。

RSS 登录恢复密钥沿用本页的恢复凭据列表/查阅入口及 Credentials 权限，轮换/核对使用现有 Credential Policy。
它只恢复 Windows 的 RSS 附加因子，仍需正确系统密码；Mac 沿用原生系统及磁盘恢复。
普通列表和事件不返回秘密，系统密码与 Secure Token 不作为可查阅 RSS 恢复材料。


### 离职处置和恢复

绑定 action `offboard` 固定目标人员及其全部当前绑定，先提交本地禁止新 DA 授权的状态，
随后在 `/devices/{device}/device-access/operations/{operationId}/offboarding` 查询分项进度。
POST 子路径 `/identity` 的 `{kind:"execute"}` 使用当前管理员会话停用目标成员并撤销其会话；
需要重新认证时保留 requires_authentication，不保存管理员 session secret。
未知结果使用 `{kind:"reconcile"}` 查询，URL 的 `limit/cursor` 控制按 Identity principal 顺序的有界实时观察；不支持筛选、重排序或字段投影。响应 `nextCursor` 是绑定操作者权限、设备和离职操作的签名游标，继续通过 `cursor` 传回。它不承诺 Identity 账号快照，也不以未找到账号证明撤销成功。

POST 子路径 `/idp` 使用 `{kind:"execute",target,action:"disable_account"|"revoke_sessions"}`，
target 来自被冻结的分项 ID；先确认账号停用，再撤销会话。使用 `{kind:"reconcile",target}`
读取真实 IdP 状态；负面观察不允许重放未知效果。设备处置沿原任务链恢复，离线时整体保持未完成。
`reinstate` 是另一次 step-up 授权：还需当前 Identity 主体有效且旧外部未知/执行中分项已经核对。
它不会恢复旧绑定、因子或 PSSO 凭据，旧 offboard operation 也不能继续处置新绑定。

DA 因子材料通过 `/devices/{device}/device-access/materials/{id}/versions/{version}/step-up`
发起 WebAuthn，完成 Identity ceremony 后 POST 同级 `/secret`，携带 `{operationId}`。
成功重试保留原 operationId；回执不含秘密，每次披露仍复核当前权限、主体和绑定。
普通 recovery-credentials GET secret 不披露 DA 因子材料。此流程不访问个人 Vault、FileVault 或其他磁盘恢复材料。
`device.access.changed` 生命周期事件复用 Webhook Outbox，包含操作和代际事实，不携带秘密；
企业 Vault 消费者须自行按 eventId 去重并处理乱序。

### 企业接入配置

`identity.enterprise` 部署配置包含 `key_id/signing_key_file`、`clients` 和 `administrators`。
每个 client 固定 `target`（id/issuer/token_endpoint/client_id/scopes）、provider UUID、Keycloak issuer、
client_secret_file、private_ca_file、private_cidrs、backend_key_id 与 backend_secret_file。
RP assertion issuer 必须各自独立；Keycloak 专用 client 信任对应 ES256 issuer，禁止 assertion 重用，
限制有效期及 access token 到 30 秒，不授予 offline_access。backend secret 至少 43 字符，使用独立随机材料。
管理员 adapter 固定 provider/issuer/clientId/addresses 与受保护服务账号密钥文件，用于显式离职操作。

业务 RP 与人员映射由 GET/POST `/api/v1/device-access/enterprise/configuration` 管理，
写入用同路径 `/step-up` 发起证明。配置种类为 relying_party、subject、windows_key；
operationId/expectedRevision 保护幂等和 CAS。RP 固定 HTTPS callback、能力和部署指纹；
修改部署配置后先显式更新 RP revision，旧交接立即拒绝。稳定 IdP sub 永久归属其人员，不能重新分配给另一主体。
Windows key 登记使用 wire 的 KeyRegistration.signing_bytes，证明只覆盖持钥，不替代原生用户在场证明。
