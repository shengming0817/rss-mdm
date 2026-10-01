# 统一资产、Manual 与授权搜索

Inventory 是唯一字段目录和来源解析 owner，应用把解析结果送入现有 Group 条件内核。PG adapter 保留来源事实、删除墓碑、最后已知值及其原始证据。Manual 绑定稳定 DeviceId，注册替换不清空业务属性。

## 字段与状态

字段目录、类型及可用操作以 `/api/v2/asset-fields` 为准；值不隐式转换。Manual 可显式置空，标准字段禁止人工覆盖。

known/null/missing/unsupported/deleted/conflict 是明确状态。同级来源相同值合并证据，不同值返回 conflict；一条来源删除不删除另一条来源。来源必须绑定当前有效注册及 epoch。Partial 应用独立成功字段，缺失或失败字段保留此前可信事实；Failed 不清空事实，最新 CollectionRun 质量另行呈现。带 itemKey 的清单按条目身份比较，相同内容的不同返回顺序不产生冲突。

没有字段 TTL、validUntil、expiresAt、到期或延迟生效判断。所有时间仅用于溯源；改变评估时间不会改变固定规则对相同事实的结果。会话、凭据和任务期限不受此规则影响。

## API

路径前缀 `/api/v2`，使用现有权威会话；写和 POST 查询要求 Origin、X-Identity-Request、CSRF。错误返回既有产品 JSON。

| 方法、路径 | 内容 |
| --- | --- |
| GET /asset-fields | 唯一版本化目录、类型、来源优先级、敏感级别及可用操作 |
| PUT /asset-fields/{field} | Operation 包装的 put/delete，expectedRevision 为字段版本 |
| GET /asset-fields/{field}/references | Group、模板、合规及保存查询引用计数 |
| GET /devices/{id}/collections/{run} | 当前设备所属采集的冻结身份、时间、字段质量及投递状态 |
| GET /devices/{id}/inventory-lists/{field}?limit=50&cursor=… | 固定资产水位的清单分页，最多 100 条且受字节预算限制 |
| GET /devices/{id}/inventory | 统一详情，不再接受 source 参数 |
| POST /device-queries | 异步受理，Operation 包含 criteria/select/sort |
| GET /device-queries/{task} | 状态、全结果计数与结果入口 |
| GET /device-queries/{task}/items?limit=1000&cursor=… | 固定结果分页 |
| GET /device-queries/{task}/facets/{facet}?limit=1000&cursor=… | 全结果汇总分页 |
| PUT /devices/{id}/manual-fields/{key} | CAS set/null/delete |
| GET /saved-queries?after={uuid} | 本人查询，最多 100 条，含删除墓碑 |
| GET /saved-queries/{id} | 本人定义与 revision |
| PUT /saved-queries/{id} | CAS put/delete |
| POST /saved-queries/{id}/execute | 按当前权限执行，正文为 Operation，expectedRevision 为保存查询版本，input 为 `{}` |

资产响应为 `{ "asset": { "kind": "detail|page|accepted|query_status|facets|assignment|saved|saved_list|fields", ... } }`。详情/列表的 fields 以字段键索引，包含 state、sources 和原始 lastKnown 证据；Manual revisions 供下一次 CAS 使用。数组通过独立 lists 返回状态、数量、摘要、来源和起始游标；用清单接口读取条目，详情不内嵌整份大清单。

赋值例：

```json
{"operationId":"24630000-0000-4000-8000-000000000001","expectedRevision":0,"input":{"action":"set","value":{"kind":"integer","value":3}}}
```

置空和删除分别为 `input:{"action":"null"}`、`input:{"action":"delete"}`。相同操作重放原回执，异正文或旧 revision 冲突；删除保留 revision，重新赋值使用当前 revision。成功审计和回执与业务同事务，审计不存字段明文。

搜索 input 与 Group 使用相同条件；搜索外层为 operationId、expectedRevision=0、input：

```json
{"criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":3}},"select":["custom.asset_tag","custom.office_floor"],"sort":{"field":"custom.office_floor","descending":false}}
```

AND/OR 为 `{kind:"and|or",children:[…]}`；in/not_in 使用同类型 `values` 数组；is_null/is_not_null 不带操作数。Group create/rule 直接使用该 criteria；preview 异步生成成员与类型化解释页，旧同步接口和 assets 元组已移除。

## 权限、分页与保存查询

inventory_fields_write 管理目录；有权限管理员直接发布字段及启用模板，不增加申请或审批状态。删除检查引用，类型、单位、条目身份或敏感级别变化需要新字段身份。inventory_sensitive_read 控制敏感字段明文及敏感条件的配置。inventory_read 按 AllDevices/Device 并集限定候选集合，再计算匹配、总数和汇总；inventory_assign 独立授予 Manual 写。所有请求重取授权，运行中会话/来源失效会再次拒绝。Group 预览和重算还要求 inventory_read/all_devices，不能用部分设备集合替换全组成员。

个人保存查询使用当前 inventory_read，并按 tenant/instance/principal 限定本人。put 的 input 为 `{action:"put",definition:{name:"…",query:{…}}}`；不保存 cursor、结果或授权集合。删除 UUID 不复用；执行重新验证当前目录与权限。

查询返回 202 和任务入口，以已提交水位分批计算并保存不可变结果。应用保留采集质量历史，查询页与详情复用同一投影；分页期间新质量记录不改写旧结果。成员、排序和全结果汇总不加载全租户到内存。
分页有界；排序按类型化值和 DeviceId，未知值置后。游标由宿主签名，绑定主体、授权集合、结果与分页投影。
每页重新验证权限；权限集合变更返回 403，重新发起查询。事实变化不改写已完成结果。签名密钥由产品按租户持久保存，多实例与宿主重启后可继续使用同一游标；游标仍绑定结果和授权范围。
超过树、字节、访问或解释预算明确失败，不截断为完整结果。没有字段时钟触发。


汇总 assetStates 统计字段状态，分母不是设备数；matched、unknown、total 分别统计匹配、未知和授权候选设备。没有合规评估事实时不从资产缺失推断合规。采集完整性见 [Windows 管理](windows-management.md)，升级见 [运维](../deployment/operations.md)。


## 规则合规评估

合规复用上述字段目录和三值 AND/OR 条件。规则条件、严重性、平台、启停和分配共用一个版本；设备执行成功不构成合规事实。不存在宽限期、字段 TTL 或时间触发：新报告、显式字段变更、注册/来源变化、规则和组资格变化才触发评估。

| 方法、路径（前缀 `/api/v2`） | 内容 |
| --- | --- |
| GET /compliance-rules?after={uuid} | 规则分页，每页最多 50 条 |
| GET /compliance-rules/{id} | 当前规则及版本 |
| GET /compliance-rules/{id}/versions/{revision} | 历史规则定义，用于解释旧评估 |
| PUT /compliance-rules/{id} | Operation 包装的完整定义；首次 expectedRevision=0 |
| POST /compliance-rules/{id}/recompute | Operation 包装，input 为 `{}`，expectedRevision 为当前版本 |
| GET /compliance-rules/{id}/tasks/{task} | phase、processed、completed、failure 与 diagnostic |
| GET /devices/{id}/compliance | 设备汇总、各规则 current；待评估时 previous 单独标识 |
| GET /devices/{id}/compliance/history?from=…&until=…&limit=50&cursor=… | UTC 秒范围、最多 100 条，返回 nextCursor |

规则 input 示例：

```json
{"name":"企业 Agent 健康","severity":"high","enabled":true,"platform":"all","target":{"kind":"all"},"criteria":{"kind":"predicate","field":"custom.corporate_agent.healthy","op":"eq","value":{"kind":"boolean","value":true}}}
```

severity 为 low/medium/high/critical，仅用于解释；platform 为 all/windows/macos。平台选择使用冻结资产来源中的原生 Windows/Apple 注册证据，只有 Agent 或来源矛盾时为 unknown，不能按型号/版本字符串猜测平台。target 可为 `{ "kind":"groups", "ids":["组 UUID"] }`，取多个智能组的并集。每租户最多 100 条规则，每条最多 16 个组；条件沿用 Group 预算。规则停用保留历史；启用规则引用的组必须先解除分配才能删除。

写入回传 id/revision/task，重评估回传 task；任务入口为 `/compliance-rules/{id}/tasks/{task}`。写入使用相同 operationId 重放，正文变化或旧版本返回冲突。规则读、写、重评估分别要求 tenant 范围的 compliance_rule_read、compliance_write、compliance_recompute；设备当前和历史要求 AllDevices/Device 范围的 compliance_read。每次读取重新授权，历史游标签名绑定主体、租户、设备和时间筛选。

完成结论为 compliant/non_compliant/unknown/not_applicable；组资格不确定仍是 unknown。pending 只表示最新输入尚未完成，不能把 previous 当作当前合规。设备汇总优先明确失败、未知、待评估；至少一条适用规则且全部通过才是 compliant。无启用规则为 unknown/no_rules，全不适用为 not_applicable。

历史保留规则版本、字典版本、资产水位、组成员集、评估时间、原因和无原始字段值的证据引用，以及 published/superseded/failed 标识。任务按固定输入分页，只有完整运行且输入仍有效才切换当前指针；旧运行不能覆盖新事实。任务阶段为 queued、evaluating、published、superseded 或 failed；processed 只统计已提交的设备评估。组输入未就绪时保留 group_input_pending 诊断。适用性证据分别保留平台判定、来源和各组资格，原因区分 platform_not_applicable、group_not_applicable、platform_unknown、group_unknown 与事实结论。规则列表使用 nextCursor，规则读取只返回 id/revision/definition。任务计数还要求 AllDevices 范围的 compliance_read，只有规则读取或部分设备权限不能读取全租户计数。未就绪的冻结输入以 superseded 结束并保留 group_input_pending 原因，组变更或发布唤醒既有 dispatcher 创建新运行，避免无进展热重试。失败诊断和恢复复用现有 automation；资产调度依次推进 Group、Scope、Compliance 后提交同一 checkpoint，重启继续持久任务；本接口不提供自动修复或标准合规认证声明。


## 发布采集模板并复用策略

原生读取使用 Resource 的 `native_collection` 类型，版本声明包含同名 declaration、canonical JSON artifact 及 definition。definition 指定 `adapter`、`mappings`、`timeoutSeconds`、`outputBytes`：`windows_csp` 只构造 CSP Get；`apple_device_information` 使用受限 Queries；`apple_installed_applications` 读取 InstalledApplicationList。Apple 当前落地的是 MDM adapter；不把尚未接入的 DDM status channel 计为已支持。

每个 mapping 的键为字段身份，值为 `{query,pointer,columns}`。columns 为空时直接按字段类型解码；非空时把清单条目投影到声明的结构化属性。模板的 canonical JSON 是上传 artifact 的原文，发布时校验字段、来源、平台和结构。脚本与 SQL 使用已有 `script` Resource，SQL profile 为 `osquery`，执行只接受固定版本模板及声明参数。

持续采集使用 Policy action `native_collection`，绑定精确 Resource、Schedule、Frequency 和 runLifetimeSeconds；脚本/SQL 使用现有 execution action。按需读取使用现有 remote-operation 的 `collect_native` action，脚本/SQL 使用 `execute`，目标为设备集合或 Scope 的冻结结果。有 inventory_collect、resource_write、policy_write 等对应权限的管理员直接启用，无新增审批状态。一次性操作不生成长期 Policy。

`GET /api/v2/devices/{id}/collections/{run}` 返回统一进度、来源、模板版本和逐字段质量。列表字段另有 itemCount/invalidItems，终态 run 可通过 `GET /api/v2/devices/{id}/collections/{run}/fields/{field}/items?offset=0&limit=100` 分页读取逐条质量，最多1000条。无效列表保留旧可信值，质量页不回传不可信原文。

资产详情中的 lists 只返回摘要，各来源摘要自带独立游标，冲突时仍可分页检查每份来源清单。使用 `GET /api/v2/devices/{id}/inventory-lists/{field}?limit=100&cursor=…` 读取选值后的列表。游标绑定字段、设备、租户、授权范围及资产水位；后续变更不混入旧分页。完整空列表与未执行、失败、部分输出分别表达。字段和清单没有 TTL。

本地 `rss-mdm-fixture ingest-fixture` 只接受示例发布的 typed-fields-v2 collector 数据；显式设置 `MDM_COLLECTION_URL` 为有采集结果写权限的数据库身份。示例先提交冻结定义与结果，再用 `DATABASE_URL` 对应的投影运行身份提交 Observation 引用。两者不共享隐式提权或旧格式读取。
