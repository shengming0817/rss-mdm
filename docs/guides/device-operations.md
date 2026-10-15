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

读取使用 `GET /operations/{id}`（operation_read）。取消使用 `POST /operations/{id}/cancel`，正文 requestId、expectedRevision（operation_cancel）。批准使用 `POST /operations/{id}/approve`，正文 requestId、expectedRevision；lock/wipe 另须 `confirmation:{confirmed:true,expectedRegistrationId,expectedGeneration}`。批准只刷新原动作权限，不修改动作、PIN、注册或 deadline。Policy 子命令由其 owner 取消，不接受此设备取消入口。

## 结果与恢复

queued 是持久受理，published 是 Outbox 网关接纳，received 是关联原生回执。restart/lock/wipe 的 ACK 不证明终端效果，不转成已核实效果或合规。已派发未知变更不自动重发；取消、deadline、撤权和注册替换阻止后续执行，不表示副作用回滚。

503 operation_unknown 表示提交可能完成：保留原请求和 UUID，先查询并以原内容重试；404 不能证明回滚。命令、Outbox、回执和审计继续共用原事务及现有 reconcile/device-command 恢复设施，重启不产生替代 operation。

Remote 与旧通用直接命令无部署升级义务，已完整退出。当前安装 schema 不接受旧安装账本；不提供历史执行导入或兼容查询。

`GET /api/v1/operations` 保留设备、Policy、状态筛选和 kind/id 复合游标。摘要移除原始输出与诊断流，完整证据沿 detailUrl 检查当前设备范围权限。脚本、原生采集、配置和软件继续走各自 Policy owner，见[企业任务](enterprise-tasks.md)。

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

`GET /api/v1/device-views` 在服务端按当前可见关联归并，再执行 status/channel/source 筛选、计数和分页。统计分别提供 endpointCount 和 deviceViewCount。详情使用 `/api/v1/device-views/endpoint/{device}` 或 `/api/v1/device-views/association/{id}`；原 `/devices` 继续表达注册端点。主通道的 children 展示当前父注册下各 purpose 的最新子注册，保留父子注册、代次、生命周期和 ready；撤销子注册不替换或撤销主通道。Windows Full 的 userContext 保留原生用户上下文及其父注册状态，不表示用户在线或动作可执行。仅看见一个成员时返回普通端点，不披露关联、另一成员或其数量。

后台按当前已认证采集来源的序列号或硬件 UUID 自动关联同租户的 MDM、Agent 主注册。值须有效、匹配、无其他有效字段矛盾且在当前实例中唯一；大小写与外围空白归一，序列号前导零和标点保留。占位值、主机名、MAC、登录用户和 Manual 赋值不参与自动确认。已关联的两个端点算一个实例。新注册代际有相同证据时自动延续；暂未上报时保留成员和历史，后续上报重新判断。重复、冲突或失效的注册显示 needs_verification。

异常通过 `GET /devices/{device}/association-candidates?channel=mdm|agent` 选定当前主通道，使用 `POST /device-associations` 明确确认。请求携带 operationId、associationId（新建为 null）、expectedVersion、mdm/agent 的 device、channel、registrationId、generation，以及核实记录 evidence。两个端点均须有当前 inventory_read 和 device_association_write。撤销用 `POST /device-associations/{id}/revoke`，携带 operationId、expectedVersion 和 reason；成员立即释放，同一对端点不会自动合回，显式确认可恢复。重试保持相同 operationId 和请求内容。变化历史从 `GET /device-associations/changes` 读取原审计事实。`nextCursor` 继续当前固定上界的分页，末页返回 `checkpoint`；后续将 checkpoint 作为 cursor 参数传回，即从已扫描位置读取新变化，空页也保留 checkpoint。两者均绑定租户、用户与实时权限；权限变化后须重新查询。每条可见变化的 position 用于消费去重。

字段沿用原有字段优先级策略，各端点的 Manual 值独立保留，同优先级不同值为 Conflict。列表显示每个端点来源的状态、证据及 cursor；以详情返回的来源 cursor 调用 `GET /device-views/{kind}/{id}/inventory-lists/{field}?cursor=...&limit=...`。分页不对不同来源的列表做集合拼接，采集完整性和失败信息保留在 inventorySources。游标签名绑定用户、权限和查询快照；响应 `device_view_cursor_invalidated` 时从第一页重新查询。
