# 统一资产、Manual 与授权搜索

Inventory 是唯一字段目录和来源解析 owner，应用把解析结果送入现有 Group 条件内核。PG adapter 保留来源事实、删除墓碑、最后已知值及其原始证据。Manual 绑定稳定 DeviceId，注册替换不清空业务属性。

## 字段与状态

字段目录、类型及可用操作以 `/api/v1/asset-fields` 为准；值不隐式转换。Manual 可显式置空。UUID、SN、manufacturer 与通道维护字段受保护；其它标准字段与 custom 字段共享目录生命周期，人工写入须由字段的 manual/source 明确允许。租户创建事务一次性写入标准定义；读取只读数据库，初始化不覆盖租户修改，也不复活已退役字段。

known/null/missing/unsupported/deleted/conflict 是明确状态。同级来源相同值合并证据，不同值返回 conflict；一条来源删除不删除另一条来源。来源必须绑定当前有效注册及 epoch。Partial 应用独立成功字段，缺失或失败字段保留此前可信事实；Failed 不清空事实，最新 CollectionRun 质量另行呈现。带 itemKey 的清单按条目身份比较，相同内容的不同返回顺序不产生冲突。

没有字段 TTL、validUntil、expiresAt、到期或延迟生效判断。所有时间仅用于溯源；改变评估时间不会改变固定规则对相同事实的结果。会话、凭据和任务期限不受此规则影响。

## API

路径前缀 `/api/v1`，使用现有权威会话；写和 POST 查询要求 Origin、X-Identity-Request、CSRF。错误返回既有产品 JSON。

| 方法、路径 | 内容 |
| --- | --- |
| GET /asset-field-layout | 本租户共享布局、revision 与当前 editable 能力 |
| PUT /asset-field-layout | Operation 包装的完整布局替换，expectedRevision 为布局版本 |
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
| GET /saved-queries?filter&sort&fields&limit&cursor | 本人查询，最多 100 条，含删除墓碑 |
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
{"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":3}}},"select":["custom.asset_tag","custom.office_floor"],"sort":{"field":"custom.office_floor","descending":false}}
```

AND/OR 为 `{kind:"and|or",children:[…]}`；in/not_in 使用同类型 `values` 数组；is_null/is_not_null 不带操作数。Group create/rule 直接使用该 criteria；preview 异步生成成员与类型化解释页，旧同步接口和 assets 元组已移除。

## 共享扩展字段分组

`GET /api/v1/asset-field-layout` 返回 `asset.kind=field_layout`、`revision`、`editable` 和有序 `groups`。
每组包含稳定 UUID `id`、`name` 和有序真实字段键 `fields`。无配置为 revision 0、空分组。
具有租户 `inventory_fields_write` 时读取完整有效映射元数据；普通资产读者只取得当前权限允许的映射，
过滤后无字段的组不返回。管理员能编辑敏感字段引用，不因此获得敏感资产值读取权限。

PUT 的 `input` 为 `{ "groups": [{ "id": "<uuid>", "name": "采购", "fields": ["custom.asset_tag"] }] }`，
使用已有 Operation 的 operationId/expectedRevision。数组顺序就是展示顺序；同一字段可出现在多个组，
同组不重复。名称去首尾空白后为 1–40 字符；每个保存的组至少选择一个当前有效的 custom 字段。
请求及持久化文档有界，超限明确拒绝。PUT 返回 `asset.kind=field_layout_written` 和新 revision。

只有字段管理者能保存共享布局；应使用其完整配置读取结果编辑，不能把普通读者的过滤投影当作完整配置覆盖。
空 groups 清空布局并递增 revision。布局只改变展示，不改变字段来源、人工资格、资产值或设备组计算；
未映射字段仍可由前端在默认扩展分类中展示。
字段退役不受展示引用阻止，GET 忽略失效引用且不改 revision；管理员下一次保存须补选或移除空组，
完整替换后自然清理失效引用。移除分组或映射不会删除字段及资产值。

保存、操作回执和业务审计同事务提交。旧 revision 或同 operationId 异正文返回冲突。
网络错误或 `operation_unknown` 不能由当前 GET 证明原写结果；用户明确恢复时沿原 operationId、
expectedRevision 和完整正文重试，返回原回执，随后重新 GET 当前布局。禁止自动换 ID 或覆盖冲突。
回执仅含 revision，重放仍重新授权。

## 权限、分页与保存查询

inventory_fields_write 管理目录并允许读取配置所需的字段定义，独立于设备资产值读取权限；有权限管理员直接发布字段及启用模板，不增加申请或审批状态。删除检查引用，类型、单位、条目身份或敏感级别变化需要新字段身份。inventory_sensitive_read 控制敏感字段明文及敏感条件的配置。inventory_read 按 AllDevices/Device 并集限定候选集合，再计算匹配、总数和汇总；inventory_assign 独立授予 Manual 写。所有请求重取授权，运行中会话/来源失效会再次拒绝。Group 预览和重算还要求 inventory_read/all_devices，不能用部分设备集合替换全组成员。

个人保存查询使用当前 inventory_read，并按 tenant/instance/principal 限定本人。put 的 input 为 `{action:"put",definition:{name:"…",query:{…}}}`；不保存 cursor、结果或授权集合。删除 UUID 不复用；执行重新验证当前目录与权限。

查询返回 202 和任务入口，以已提交水位分批计算并保存不可变结果。应用保留采集质量历史，查询页与详情复用同一投影；分页期间新质量记录不改写旧结果。成员、排序和全结果汇总不加载全租户到内存。
分页有界；排序按类型化值和 DeviceId，未知值置后。游标由宿主签名，绑定主体、授权集合、结果与分页投影。
每页重新验证权限；权限集合变更返回 403，重新发起查询。事实变化不改写已完成结果。签名密钥由产品按租户持久保存，多实例与宿主重启后可继续使用同一游标；游标仍绑定结果和授权范围。
超过树、字节、访问或解释预算明确失败，不截断为完整结果。没有字段时钟触发。


汇总 assetStates 统计字段状态，分母不是设备数；matched、unknown、total 分别统计匹配、未知和授权候选设备。没有合规评估事实时不从资产缺失推断合规。采集完整性见 [Windows 管理](windows-management.md)，升级见 [运维](../deployment/operations.md)。


个人保存查询列表响应为 `asset.kind=saved_list`、`asset.items`、`asset.nextCursor`。
保留本人 tenant/instance/principal 边界和删除墓碑；可用 `filter=deleted==false` 隐藏墓碑。
目录参数、投影及续页语义见[统一目录查询](groups-scopes-policies.md)，与异步资产结果页分别拥有游标。

## 规则合规评估

合规复用上述字段目录和三值 AND/OR 条件。规则条件、严重性、平台、启停和分配共用一个版本；设备执行成功不构成合规事实。不存在宽限期、字段 TTL 或时间触发：新报告、显式字段变更、注册/来源变化、规则和组资格变化才触发评估。

| 方法、路径（前缀 `/api/v1`） | 内容 |
| --- | --- |
| GET /compliance-rules?filter&sort&fields&limit&cursor | 规则分页，每页最多 50 条 |
| GET /compliance-rules/{id} | 当前规则及版本 |
| GET /compliance-rules/{id}/versions/{revision} | 历史规则定义，用于解释旧评估 |
| PUT /compliance-rules/{id} | Operation 包装的完整定义；首次 expectedRevision=0 |
| DELETE /compliance-rules/{id} | Operation 包装删除当前规则，保留历史；释放当前依赖 |
| POST /compliance-rules/{id}/recompute | Operation 包装，input 为 `{}`，expectedRevision 为当前版本 |
| GET /compliance-rules/{id}/tasks/{task} | phase、processed、completed、failure 与 diagnostic |
| GET /devices/{id}/compliance | 设备汇总、各规则 current；待评估时 previous 单独标识 |
| GET /devices/{id}/compliance/history?from=…&until=…&limit=50&cursor=… | UTC 秒范围、最多 100 条，返回 nextCursor |

规则 input 示例：

```json
{"presentation":{"name":"企业 Agent 健康"},"severity":"high","enabled":true,"platform":"all","target":{"kind":"all"},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.corporate_agent.healthy","op":"eq","value":{"kind":"boolean","value":true}}}}
```

severity 为 low/medium/high/critical，仅用于解释；platform 为 all/windows/macos。平台选择使用冻结资产来源中的原生 Windows/Apple 注册证据，只有 Agent 或来源矛盾时为 unknown，不能按型号/版本字符串猜测平台。target 可为 `{ "kind":"groups", "ids":["组 UUID"] }`，取多个智能组的并集。每租户最多 100 条规则，每条最多 16 个组；条件沿用 Group 预算。规则停用保留历史；启用规则引用的组必须先解除分配才能删除。

写入回传 id/revision/task，重评估回传 task；任务入口为 `/compliance-rules/{id}/tasks/{task}`。写入使用相同 operationId 重放，正文变化或旧版本返回冲突。规则读、写、重评估分别要求 tenant 范围的 compliance_rule_read、compliance_write、compliance_recompute；设备当前和历史要求 AllDevices/Device 范围的 compliance_read。每次读取重新授权，历史游标签名绑定主体、租户、设备和时间筛选。

完成结论为 compliant/non_compliant/unknown/not_applicable；组资格不确定仍是 unknown。pending 只表示最新输入尚未完成，不能把 previous 当作当前合规。设备汇总优先明确失败、未知、待评估；至少一条适用规则且全部通过才是 compliant。无启用规则为 unknown/no_rules，全不适用为 not_applicable。

历史保留规则版本、字典版本、资产水位、组成员集、评估时间、原因和无原始字段值的证据引用，以及 published/superseded/failed 标识。任务按固定输入分页，只有完整运行且输入仍有效才切换当前指针；旧运行不能覆盖新事实。任务阶段为 queued、evaluating、published、superseded 或 failed；processed 只统计已提交的设备评估。组输入未就绪时保留 group_input_pending 诊断。适用性证据分别保留平台判定、来源和各组资格，原因区分 platform_not_applicable、group_not_applicable、platform_unknown、group_unknown 与事实结论。规则列表使用 nextCursor，规则读取只返回 id/revision/definition。任务计数还要求 AllDevices 范围的 compliance_read，只有规则读取或部分设备权限不能读取全租户计数。未就绪的冻结输入以 superseded 结束并保留 group_input_pending 原因，组变更或发布唤醒既有 dispatcher 创建新运行，避免无进展热重试。失败诊断和恢复复用现有 automation；资产调度依次推进 Group、Scope、Compliance 后提交同一 checkpoint，重启继续持久任务；本接口不提供自动修复或标准合规认证声明。


## 发布采集模板并复用策略

原生读取使用 Resource 的 `native_collection` 类型，版本声明包含同名 declaration、canonical JSON artifact 及 definition。definition 指定 `adapter`、`scope`、`applicability`、`mappings`、`timeoutSeconds`、`outputBytes`：`windows_read` 将类型化标量或固定动态命名空间编译为只读 CSP Get；`apple_device_information` 使用受限 Queries；`apple_installed_applications` 读取 InstalledApplicationList。Apple Inventory 采集使用 MDM adapter；DDM 状态由 operation 原生证据查询独立呈现，不自动组成 Inventory Snapshot。

每个原生 mapping 的键为字段身份，值为 `{query,mapping:{pointer,conversion,columns}}`。脚本 purpose 的 mappings 直接使用 `{pointer,conversion,columns}`。conversion 为 identity、integer、number、enum、scale 或 bitmask；未知枚举、未知位、溢出与不能整除的单位换算均为 invalid。columns 递归声明列表属性，不复制未声明属性。模板的 canonical JSON 是上传 artifact 的原文，发布时校验字段、来源、平台和结构。脚本与 SQL 使用已有 `script` Resource，SQL profile 为 `osquery`，执行只接受固定版本模板及声明参数。

`GET /api/v1/collection-blueprints` 返回六类目录及实际可实例化的官方蓝图。Windows 六类均提供版本 2 原生模板，macOS identity/hardware 保留版本 1；Windows 支持范围、来源和样本见 [Windows 管理](windows-management.md#原生资产采集)。

使用 `POST /api/v1/resources/{id}`，请求 `{"operationId":"<uuid>","expectedRevision":0,"input":{"action":"instantiate","blueprint":"macos.hardware","version":"1"}}`，创建普通租户 Resource 并写入 canonical 内容。初始版本为 `builtin.macos.hardware.1`，revision 为 2、状态 frozen；用正常 activate 操作启用，再绑定 Policy。版本含 x86_64/aarch64 variants。管理员直接修改该 Resource 并发布新版本；官方蓝图只读，升级需创建新候选 Resource，明确调整 Policy，不能自动覆盖或合并租户内容。重复相同 operationId 可恢复实例化/上传，不接受移动的 latest 版本。

冻结 CollectionDefinition 的每个字段必须包含 `{definition,scope}`，不再接受顶层 scope 或隐式继承。Device 为默认读取范围；Apple user 使用规范 UUID，macOS 应用根与 Brew 使用下述独立命名空间。完整快照只删除当前模板选中的字段，保留同来源同范围中未选字段及其它来源值；禁用 Policy 不删除最近可信事实。

applicability 包含 minimumOsVersion、minimumBuild、editions、enrollments、tools、capabilities，空集合表示未额外限制；平台与架构由 Resource variant 持有。示例：`{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":["agent"],"tools":{"osquery":"5.23.1"},"capabilities":["osquery"]}`。预览与执行使用相同适用性检查；缺少声明所需证据不会默认匹配。Windows 原生沿用当前可信 CSP OS/build/edition 与 enrollment；Apple 原生使用实际 access rights，尚无可信版本信息时不能满足 OS/edition 限制。Agent poll 的 environment 提交 edition/tool 版本，OS/build 复用 executionContext.osVersion。这里只冻结契约，实际 Agent 采集和外部仓升级由对应平台任务交付。

Windows Firewall CSP 状态与 WSC health 使用不同字段；BitLocker conversion、protection、lock 分列。软件安装实例、receipts 与包管理器记录也分别建模。标准 seed 不代表每个平台已有采集器，支持面以可执行模板为准。

标准采集使用 Policy action `native_collection` 或 `agent_collection`，绑定精确 Resource 版本。每个包使用可调整的 interval 周期，默认为一小时；Frequency 固定为 every_trigger，misfire 固定为 coalesce_one，离线恢复只处理最近到期周期。启用持续采集，停用停止新增运行并保留可信事实；不接受手动触发或 rerun。页面刷新只读取已有资产和运行状态。符合既有授权与冻结定义的 Agent 主动报告继续由原报告入口接收。脚本/SQL 仍使用现有 execution action，一次性运维执行使用原 remote-operation `execute`；不改变其执行语义。管理员需要 inventory_collect、resource_write、policy_write 等对应权限，无新增审批状态。发布 Resource 新版本不会自动改动 Policy 的精确绑定。Agent 注册只冻结通道维护采集，Windows 会话不再自动采集固定 model/OS，Apple 旧 collection-runs 创建入口已删除；注册认证与通道维护仍由原 owner 执行。

`GET /api/v1/devices/{id}/collections/{run}` 返回统一进度、来源、模板版本和逐字段质量。列表字段另有 itemCount/invalidItems，终态 run 可通过 `GET /api/v1/devices/{id}/collections/{run}/fields/{field}/items?offset=0&limit=100` 分页读取逐条质量，最多1000条。无效列表保留旧可信值，质量页不回传不可信原文。

资产详情中的 lists 只返回摘要，各来源摘要自带独立游标，冲突时仍可分页检查每份来源清单。使用 `GET /api/v1/devices/{id}/inventory-lists/{field}?limit=100&cursor=…` 读取选值后的列表。游标绑定字段、设备、租户、授权范围及资产水位；后续变更不混入旧分页。完整空列表与未执行、失败、部分输出分别表达。字段和清单没有 TTL。

本地 `rss-mdm-fixture ingest-fixture` 只接受示例发布的 typed-fields-v1 collector 数据；显式设置 `MDM_COLLECTION_URL` 为有采集结果写权限的数据库身份。示例先提交冻结定义与结果，再用 `DATABASE_URL` 对应的投影运行身份提交 Observation 引用。两者不共享隐式提权或旧格式读取。

## 用已安装软件事实安排软件策略

`device.software.installations` 沿用现有对象数组，条目持有 id、name、version、publisher、scope。先按 `device.software.installations.id` 的 `contains_any` 条件形成智能组，再通过 Scope 分配已有 Software Policy：持续必装用 required_install，用户可选用 available_install，明确移除用 explicit_uninstall。软件不走 RemoteOperation；一次性操作入口的范围冻结见 [企业任务](enterprise-tasks.md)。

例如，清理已检测到的旧应用可对该 id 的组发布 explicit_uninstall；升级已安装应用可对同一组发布 required_install；全设备必装应对目标 Scope 发布 required_install，让当前任务的独立检测确认是否已经满足。用户已有安装同样可以满足目标，或者由有权限的任务执行升级/卸载，不以历史安装归属作为执行门槛。

检查指定软件的版本时，读取授权清单中 id 匹配的同一对象及其 version。不要将独立 id 集合条件与 version 集合条件 AND 后宣称关联到了同一软件；Group 目前没有数组条目关联语法。完整空列表可用于判定未发现目标，Missing、Unsupported、冲突或部分采集须保留未知及质量解释。软件任务结果只证明该次执行的前后检测；后续库存仍由既有采集链路产生，不能从 verified 结果伪造库存快照。

本次为当前格式替换：旧 Windows `windows_csp`、Windows 字符串 query、旧 Windows 蓝图版本 1、NativeCollection 存储版本 4 均拒绝；Apple 字符串 query 保留原协议形状。旧映射字符串、缺少 scope 的采集定义以及旧 claim payload 均拒绝。数据库新增迁移检查并拒绝不兼容的既有业务状态，不改写历史 migration digest、不自动清库或双读；升级须显式部署匹配的服务端、schema 与 Agent 候选版本。

原生 MDM 当前没有可信架构证据，因此 `native_collection` 同平台必须同时声明 x86_64 与 aarch64，且声明内容一致；架构专用原生模板会被拒绝。Agent 脚本仍按实际执行环境核对精确架构。

## Windows Agent 声明式采集

Agent 原生采集使用独立的 `agent_collection` Resource 和同名 Policy action。官方 `windows.agent.*` 模板覆盖身份/OS、CPU、内存、固件、磁盘、卷、网络、电池和软件；identity/software 当前为修订 2，其余为修订 1，经现有蓝图接口实例化为普通 Resource；选择后发布、激活并绑定精确 Policy 版本。采集固定按包周期重复：Schedule 使用 interval、Frequency 为 every_trigger、misfire 为 coalesce_one，默认每小时一次，可调整 interval.seconds。采集不接受 manual、每版本一次、维护窗口或截止日期，也不接受 Policy rerun；停用停止新增采集但保留可信资产。客户端离线后只处理最近到期周期，不堆积补跑历史周期。页面刷新只重新读取已上报的数据。能力不足不派发，失败不会改派 PowerShell；MDM CSP 模板、企业显式脚本和 osquery 各自保留。

定义包含唯一 wire plan 和服务端字段映射。WMI 只查询本机已有 namespace/class 的明确属性和结构化过滤条件；不能执行方法、远程查询或 Win32_Product。注册表明确 HKLM/HKU-SID、32/64 位视图、路径、值名和类型，只读取指定值或枚举直接子键；不使用 System HKCU，不加载离线 hive，EXPAND_SZ 不展开。UInt64/QWORD 按精确十进制文本传输，可映为字符串或受检整数；不能转换成浮点。`cim_time` 只转换日期与 UTC offset 完整的 CIM 时间。

`agent.native` 与其他来源分别保存事实，字段统一视图继续使用原有来源配置。标准字段中新来源初始优先级为 1、既有来源保持 0；数值越小越优先，可通过现有字段版本接口调整，不设置 TTL。完整查询独立更新，截断或错误列表保留旧值，完整零条列表更新为 `[]`。标量零条默认 Missing，只有冻结映射明确选择且证据完整时才发布 null/本来源删除。软件清单必须完整覆盖预期用户集合；本期不支持 SID 局部替换。

发布及执行要求 InventoryCollect 和相应资源/范围权限；敏感字段还需要既有敏感资产权限。任务领取和 Start 必须具备 `inventory.native.v1` 及 plan 所需引擎版本，无需 ScriptExecute 或 PowerShell。运行详情保存逐查询质量与结果摘要；大结果保留分块引用，不能以执行完成代替字段完整。设备运行、Windows API 正确性与性能由独立 Agent 验收证明。

### Windows 标准资产语义

identity 从 Win32_ComputerSystem 读取型号/制造商，从 ComputerSystemProduct 读取 UUID，
从 BIOS 读取序列号。edition 使用机器级 CurrentVersion/EditionID；architecture 使用机器级
Session Manager/Environment/PROCESSOR_ARCHITECTURE，映射 AMD64/ARM64 为 x86_64/aarch64，
不读取可能受仿真影响的进程环境。注册表来源参考[微软 WSL 实现](https://github.com/microsoft/WSL/blob/6747ae808acd3895ed1b23ffdb8aa9d4b6978066/tools/deploy/deploy-to-host.ps1#L13-L17)。

Inventory 统一验证序列号/UUID，占位值、非法 UUID 为 Invalid，缺属性为 Missing；
两者均不生成删除或替代身份。规则同样适用于自定义映射，设备关联复用相同判定。
合法序列号修剪空白并统一为大写，UUID 使用规范小写格式；原始结果和摘要保持不变。

软件 installations 每项必须包含 installation_state：Win32 卸载记录为 installed，
MSIX 用户注册为 registered，设备预配为 provisioned。用户记录保留 owner SID，设备记录 owner 为空；
预配只说明未来用户注册的准备状态，不证明现有用户已安装。origin、native_id 和实例 id 保留原始来源坐标，
同包跨用户以及注册/预配分别成项。状态与来源或范围矛盾、未知 Windows 来源、非法行或覆盖不足
均不能发布部分清单；完整零条才能更新为空。receipts/packages 不增加该状态属性。

磁盘 id 使用 Win32_DiskDrive.DeviceID，表示当前本机磁盘实例，不承诺跨重启永久身份，
不与旧 PNPDeviceID 派生值自动关联。卷使用 DeviceID 标识、Name 展示。CPU 完整汇总核心数，
型号不一致时省略 model；多电池使用能量加权百分比，无法可靠计算时保留对应质量，不能退回首包值。

当前字段基线直接替换旧 installations 结构，缺少 installation_state 的旧数据不被补默认值。
identity/software 修订 1 蓝图退出；没有旧部署迁移或兼容读取，已有字段类型不可变规则仍然适用。
服务端接缝测试与 Windows 真机证据分别记录，x64/ARM64 实机支持须由产品 T3 验证。

### macOS Agent 声明式采集

`macos.agent.*` 蓝图提供设备级硬件与 PKG 收据采集，沿用上述 Resource、Policy、
CollectionRun 和字段质量流程。收据独立写入 `device.software.receipts`，不作为应用存在证据。
APFS container 原始证据与卷关联保留在受限运行详情中，共享容量不相加。
`applications_local`、`applications_system`、`applications_user` 分别采集 /Applications、/System/Applications 和当前绑定用户的 Applications；完整清单只替换该根范围。`brew_arm_formula`、`brew_arm_cask` 使用 /opt/homebrew，`brew_intel_formula`、`brew_intel_cask` 使用 /usr/local；formula/cask 写入 `device.software.packages`，与 receipts、installations 分开。

用户应用与 Brew 只在可信执行上下文的当前非 root 登录用户下派发；固定 UID 等待该用户匹配。历史用户的事实仍可按 scope 查询、用于规则，读取不要求该用户现在登录。Offer 只构建一次 payload，从同一执行绑定冻结 UID/字段 scope、预留 CollectionRun，再签名；发布阶段不注册未绑定用户的完整采集定义。

字段 scope 支持 `device`、`apple_user`、`macos_applications`、`macos_brew`。应用 scope 包含 root（local/system/user）和 uid（仅 user 非空）；Brew 包含 uid、prefix、package（formula/cask）、taps。dataset 绑定 Resource/variant/实际用户及稳定 GeneratedUID（适用时），不包含版本、会话或预算；变更某字段 root/prefix/taps 只创建该字段的新范围，不自动删除旧范围。

设备已有的非 Device 范围通过 `GET /api/v1/devices/{id}/inventory-scopes?limit&cursor` 发现，响应为资产 envelope 的 `inventory_scopes {device,watermark,items:[{scope}],nextCursor}`。目录仅列当前有效来源的冻结采集尝试或保留事实，先按当前敏感字段权限过滤，再按固定水位和不透明游标分页；运行清理不隐藏仍保留的可信事实。权限、来源或注册世代变化使旧游标冲突，应从第一页重取。空目录不证明设备没有其它真实用户；Device 范围独立读取。

详情、清单和运行详情通过 `scope=<URL 编码的 scope JSON>` 显式选择范围，省略则 Device。运行详情提供 frozen fingerprint/coverage、逐字段 scope/reason、完整性，以及实时 Observation receipt/projection 状态。固定水位质量记录不会被实时状态改写；quality.runId 是最近尝试，sources.evidence.snapshotId 是当前可信事实的原始 run，lastKnown 继续保留原始证据。失败和部分尝试不清空此前 Known；显式 Unknown 不通过规则。

查询、保存查询、智能组及合规的 criteria 使用同一 `{selector,quantifier,criteria}`。selector 为 `{"kind":"device"}`、`{"kind":"exact","scope":…}`、`{"kind":"local_user","platform":"macos","identity":"501"}` 或 `{"kind":"all_authorized"}`。前两种 quantifier 必须 one，多范围必须 any/all。多范围集合只包含固定水位下已冻结、且调用者有权读取的资产范围；all_authorized 不表示已枚举设备上的所有真实用户。整个内层条件先在每个 scope 独立求值，再归约成设备结果；不拼接不同用户事实。空集合为 Unknown，集合不完整时 all 不能通过，字节、访问和解释预算跨所有上下文累计。授权仍独立限制设备和敏感字段。Group scope 元数据与核心 rule_version 同事务冻结，核心继续拥有条件和实际分页求值。

旧定义、结果、事实历史、冻结策略或待执行旧任务存在时，新增安装迁移拒绝继续；不转换旧格式、清库或改写历史 migration digest。新的投影 generation 只重放新格式。
协议身份、支持边界与 Agent 接入见 [wire 契约](../../crates/agent-wire/README.md#macos-原生采集2737)。

### Agent 安全、账户、证书与更新标准包

蓝图目录中的 `windows.agent.*` / `macos.agent.*` 安全、身份与更新包仍通过普通 Resource 实例化、
修改、发布和 Policy 分配。设备包与用户证书包分别选择；用户包等待当前已绑定 helper，
不会切换到离线用户或以 System 身份伪装用户授权。具体清单及适用要求由蓝图目录返回。
新包的操作系统门槛和 BitLocker edition 条件只用于任务准入；实际支持仍须经过产品真机验收。

证书字段范围为 `native_certificates`，显式携带 platform、owner 和 store；owner 为 null 表示机器，
Windows 用户为 `{kind:"windows",sid:…}`，macOS 用户为 `{kind:"macos",uid:…,generated_uid:…}`。
账户批准集合、指定应用和用户 Token 分别使用自己的 native 范围，不借用软件范围或 Device。
同一证书出现在两个 store 属于两个独立事实。合法完整空仅替换对应范围；失败、部分和截断保留旧值。

`local_user` 选择器显式提供 platform 与 identity：Windows 为 SID，macOS 为规范数字 UID。
macOS UID 查询可以返回该 UID 下多个独立历史范围，不能据此认定相同 GeneratedUID；需要一个确定账户
时使用 exact 范围。多范围规则仍逐范围求值，不能拼接不同账户或不同 store 的事实。

更新默认选择 `_local` 包；主动只读联网查询选择 `_online` 包，二者都不授权更新部署。
查看实际来源、模式、扫描区间和质量，不能把缓存或失败的空输出解读为没有可用更新。
配置/运行、FileVault/硬件加密/Token 和本地注册/有效管理保持独立语义，MDM/DDM 来源继续分别保留。
账户、证书、会话、应用权限和用户 Token 证据需要敏感权限；原始运行证据仍执行相同限制。

包含 System recipe 的新标准包总输出最多 1 MiB，只接受校验后的 inline 结果。达到预算报告 Truncated，
保留旧事实；不接受原始分块绕过字段检查。本候选只用于匹配安装 manifest 的实例，旧查询/规则/资源
不能直接原地切换；不通过清库或重新注册绕过安装拒绝。

System 标准字段保持规范映射，不能将 subject 改写为 owner、替换 store、将安装存在映射为健康，
或把缺失观察改成删除。需要派生解释时使用自定义字段。Windows 系统服务账户不能作为用户采集的交互绑定。

## 遥测配置与历史查询

先用 `POST /api/v1/asset-retention-policies` 发布保留策略，再在字段定义的
`timeSeries` 中引用精确 key/revision。发布请求沿用 `Operation`，`expectedRevision`
为前一版本；`GET /api/v1/asset-retention-policies/{key}/{revision}` 读取该历史版本。
策略的原始数据、汇总及删除恢复时长互相约束，已发布版本不可原位改写。资产当前值仍无 TTL。
字段类型、单位、Counter 含义变化须使用新字段身份。引用检查区分活跃采集模板、遥测
Profile 与归档资源版本；归档引用只解释历史。

Resource 的 `telemetry_profile` 版本绑定一个精确的原生、脚本或 osquery 模板，冻结字段
定义、采样/上传周期、执行与输出预算，并选择 current/history/both 投影。字段绑定持有
保留策略，Profile 不能覆盖。数组必须声明稳定 item key；标量值和维度使用显式属性路径，
维度值域必须有限。提频使用绝对 UTC 到期时间，读取配置不会续期。
展示与厂商说明使用 Resource 的 `presentation`，编辑展示不改变已发布执行版本或上传绑定。
遥测中的额外普通字段和对象属性受原始输入预算约束，并参与完整输入幂等；只有配置字段及
其声明属性进入当前资产、历史样本和字段质量统计。原始输入由现有 Outbox 持有，不通过
资产或历史查询返回，也不因时序保留策略到期而自动清理。

Policy 的 `telemetry_profile` action 使用精确 Resource 版本和现有设备 Scope。
Agent 在现有 mTLS runtime 边界读取
`/telemetry/configurations/{policy}/{version}`，通过 `POST /telemetry/batches` 上传，
再用 `GET /telemetry/batches/{id}` 查询原身份结果。相同身份异内容冲突；提交未知时保留
原批次 ID，不生成替代 ID。只有已声明 `telemetry.collect.v1` 且平台/架构匹配的主 Agent
注册可调用。周期采样和离线缓存由 Agent 后续实现，本服务端契约不代表真机采样已验收。

批次的 `published` 表示所需后端或当前资产 inbox 已确认接收。当前资产是否完成投影，
使用 `GET /telemetry/batches/{id}/observations/{observation}` 单独查询。历史数据是否仍
可查询由查询结果的 unavailable 范围表达；指定汇总窗口的进度也独立于批次接收。

管理端使用以下受现有会话/设备 Scope 保护的接口：

| 接口 | 用途 |
| --- | --- |
| GET /api/v1/devices/{device}/telemetry-configurations | 当前主 Agent 可下发配置摘要及采集能力，不代表设备已接收 |
| POST /api/v1/telemetry/history | 精确设备、字段、资源的历史或 latest；历史续页重新授权 |
| POST /api/v1/telemetry/aggregate | 精确字段历史版本、来源代际、维度及窗口的聚合 |
| POST /api/v1/telemetry/health | 接收时间窗口内的批次状态及 valid/missing/failed 计数 |
| POST /api/v1/telemetry/maintenance | 原身份下执行有界重算、保留边界、清理、删除或恢复步骤 |

配置摘要要求当前设备的 `inventory_read` 和租户 `policy_read`、`resource_read`，不要求全部设备读取权限。
摘要与 Agent 目录复用当前发布者授权、Scope、注册来源、字段准入和能力判定，不返回脚本、参数、签名或采样值。
无可用采集注册时返回空注册与空配置；候选方案超过目录预算时明确失败，不返回部分集合。

查询观察时间使用 UTC Unix 微秒，窗口为左闭右开。latest 按活跃注册、来源优先级及观察
顺序选择；相同优先级的冲突被显式报告。latest 需要在有界资源范围内完成来源比较，预算
不足时返回失败；历史查询使用游标。Counter 必须携带累计重置起点或增量区间；缺失、失败、
边界和覆盖缺口不补成零。

敏感字段在历史、聚合和健康读取中都要求额外权限。维护操作还要求设备范围内的
`telemetry_maintain`，删除/恢复要求 `telemetry_delete`。维护请求的 ID 绑定完整内容，
每次调用重新授权；`more` 需要以相同请求继续，`blocked` 表示依赖尚未满足，不能当作成功。
删除恢复使用原 selection、窗口和 fence；后台存储继续保护恢复期、汇总边界与幂等承诺。

Agent 从 runtime 的 `GET /telemetry/configurations` 发现当前授权分配，再获取精确 Policy/version 配置。目录是有界完整集合，超出容量明确失败，不把部分结果当作撤销清单；当前最多扫描 256 个启用的遥测 Policy。目录中的 `supported=false` 表示现有能力或环境不满足，不能降级执行。配置含原生计划或脚本字面量输入、显式映射、字段定义与配置绑定；上传必须原样回传绑定。脚本内容从该精确配置的 `/content` 路径获取，重新检查注册、Scope 和发布者权限并验证字节摘要。

Profile 参数经精确模板校验，不做文本插值；当前设备遥测仅接受 Device/System 模板。临时提频到达 UTC 到期时间后恢复正常周期，不因重新拉取配置而续期。历史补传同时受 Profile backfill 与字段绑定保留期限约束；旧定义继续按原版本解释。

周期原生性能模板可使用 `windows_performance` / `macos_performance` query，声明对应
`windows.performance` / `macos.performance` V1 engine；section 为 `cpu`、`memory`、`file_systems` 或 `network`。
CPU `busy_percent` 是至少 250ms 双读窗口的百分比；内存与文件系统容量、网络累计字节均使用精确 UInt64 十进制字符串，
数值字段通过显式受检 Integer 转换，超范围不截断。文件系统/网络以 `id` 为实例键；网络值是可重置累计计数，不是速率。
沿已有 `agent_collection` Resource → `telemetry_profile` → Policy 发布，字段与保留策略仍由租户显式选择；不自动修改静态资产字段。
按接口的历史累计 Counter 使用显式 `counterNormalization: "local_cumulative_v1"` 映射，要求 Agent 声明
`telemetry.counter.local.v1`。字段声明稳定 `item_key`、计数 `value_path` 和整数 `interval_start_path`；
起点由 Agent 的持久基线生成，来源映射不得同时提供该属性。首次采集、计数回退或来源生命周期变化先报告缺失预热，
后续上传相对基线的累计增量及逐接口起点，由历史查询计算 increase/rate。该标记仅用于周期网络性能采集，不能用于普通资产采集。

Agent 可向 runtime 的 `POST /telemetry/gaps` 提交固定 `TelemetryGapReport`，未知结果用
`GET /telemetry/gaps/{reportId}` 恢复。原 reportId、registrationId、generation、createdAt 与内容在重试期间保持不变，
收到 durable receipt 后仅清除该快照；新缺口不能被旧回执清掉。原注册失效后不能将其缺口归入新注册。
这类诊断不携带 Policy/field，也不证明连续缺失或真实覆盖率；时间跨度只给出首末观测界限。
接收/幂等期限及容量见 [telemetry owner](../../crates/telemetry-service/README.md)。
管理端 `POST /api/v1/telemetry/gaps/query` 接收 device、receivedFrom/receivedUntil（UTC 微秒）、limit（1–256）、
after（上一页 next 或 null），返回 reports 与 next；每页按当前 `inventory_read` 设备范围授权。
诊断查询不暴露采样值，也不替代 `/telemetry/health` 的批次质量统计。

合规规则的停用与删除分别表达。`DELETE /api/v1/compliance-rules/{id}` 接受
`{operationId,expectedRevision,input:{}}`，退出当前评估、释放当前组/字段引用及规则配额；
同操作重试返回原回执，在途旧任务结算为 superseded。删除后普通 Get 为 404，原 ID 不可重建；
历史版本和设备评估仍可读取，`filter=deleted==true` 可发现规则墓碑。只支持当前 V1 全新安装，不提供旧库升级。
