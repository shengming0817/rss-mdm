# 组、范围与 Policy

Group 持有成员求值；Scope 组合目标并集、限制并集和排除并集；Policy 持续引用 Scope 并分配闭合 Action；资源绑定位于需要资源的 Action 内。管理入口是 `/api/v1`，资源入口是 `/api/v1`。写入带 operationId、expectedRevision、input；提交未知时重试原身份和原文档。

目录读取使用 `GET /api/v1/groups`、`/scopes`、`/policies` 和 `/resources`，返回 `items/nextCursor`。
这些目录统一使用 `filter/sort/fields/limit/cursor`，不再接受 `after/descending` 或旧的散列过滤参数。
例如 `/api/v1/groups?filter=kind==static;name=icontains=office&sort=name&fields=id,presentation&limit=20`，
`/api/v1/scopes?filter=ready==true`，以及
`/api/v1/policies?filter=state==disabled;category==selfservice&sort=-revision`。
Group、Scope 缺省排除删除记录；需要墓碑时显式使用 `filter=deleted==true`。
Resource 示例为 `/api/v1/resources?filter=kind==script;active==false&sort=kind,-revision&fields=id,presentation&limit=20`。
`filter` 是有界 RSQL 子集，分号表示 AND、逗号表示 OR（AND 优先），支持括号、引号、转义及
`== != =lt= =le= =gt= =ge= =in= =out=`；新增目录的 Text 字段还支持字面、不区分大小写的 `=icontains=`；不支持的字段、类型、操作和重复参数返回 400。
完整字段与类型、过滤／排序／返回能力由 [Resource 字段定义](../../crates/resource/src/directory.rs) 持有；
开发者可用 `python3 hack/build_run.py -- cargo run --locked -p rss-mdm-management-http --example resource_query`
读取同源契约说明。解析预算见 [query 参数入口](../../crates/query/src/parameters.rs)和[解析器](../../crates/query/src/parser.rs)。

目录缺省按唯一身份升序；显式排序缺少唯一键时追加 ID 升序，同值排序可以稳定续页。
缺省 fields 返回完整目录头；显式空 fields 拒绝，部分投影只包含所选字段，不能用来覆盖完整编辑对象。
`presentation` 整体保留扩展键，不能用任意扩展 key 过滤或排序。没有无条件总数查询。
续页将 nextCursor 原样作为 cursor，保持过滤、排序、投影不变；可以调整合法页大小。
末页返回 null；签名或查询／主体／授权上下文失效返回 409（Resource 为 `resource_cursor_invalidated`，其余目录使用所属服务的 conflict 错误），应从首页重查；
当前权限不满足仍返回 403。游标不是权限证明，也不要求客户端解析。
每页读取当前状态，数据不变时不重不漏；跨页修改排序值或集合内容可能使结果移动，不提供快照一致性。
管理能力声明位于 [资源目录](../../crates/http-contract/src/catalog.rs)和[现有集合描述](../../crates/http-contract/src/collections.rs)。
运行 `python3 hack/build_run.py -- cargo run --locked -p rss-mdm-management-http --example management_capabilities`
可读取类别、当前分页／默认排序、字段 owner 引用与迁移缺口。已迁移目录的 List 注册绑定执行所用的领域字段声明；缺绑定、错资源或缺必需入口均拒绝。
中央目录不复制过滤、排序或输出字段表，字段以实际 owner 的 `SCHEMA` 为准。声明明确区分完整集合、变化事件流、异步结果页和当前选项；
`Pending` 表示已有执行路径仍待迁移，缺少排序、无分页或无续页标记都不算标准查询已完成。

旧查询参数与列表 DTO 直接退出；本批仅交付后端，前端由 #2903 承接。前端应同步参数、字段投影与不透明游标，完成前不能将新后端与旧前端作为已完成组合发布。

Policy 默认不列出 archived；指定 `filter=state==archived` 查询历史对象。目录每页读取当前一致视图，不冻结跨页业务状态。

Policy 响应使用 `state: enabled | disabled | archived`，不返回 enabled 布尔字段。
创建/更新仍通过 POST 的 put，输入 enabled 表达本次启停意图；enable/disable 为显式变更。
`DELETE /api/v1/policies/{id}` 接收 `{operationId, expectedRevision}`，仅允许 disabled 策略归档，返回归档后的对象。
同 operation 重试恢复原回执；不同输入或过期 CAS 返回冲突。归档后不能编辑、启用或 rerun，保留版本、资源引用、执行及审计历史。
既有任务的结算、未知恢复和配置撤回继续执行。没有物理删除或恢复接口。

`GET /api/v1/devices/{device}/groups?limit&cursor` 反查已发布成员关系，要求 GroupRead 和全设备 InventoryRead。
响应区分 endpoint 与 association 对象，包含成员/规则版本和评估新鲜度；stale 不表示当前仍满足规则。
空列表不证明所有组都已计算或均不匹配。权限与设备绑定的游标不能用于另一设备。

创建 Group 必须声明不可变 `assetContext: endpoint | associated_device`。静态组只接受 endpoint；成员、差分与决策使用 `{kind: endpoint | association, id}`。endpoint 组仍求值原始终端；associated_device 组以关联对象和独立终端为完整对象域，并保留原始注册、世代与字段来源。动态组创建或规则变化自动计算，相关事实按字段和设备增量求值，必要时全算。静态组使用 add/remove。预览保存独立计算结果，不发布正式成员、不产生执行。计算检查点固定输入水位并分页恢复；新输入合并到待处理水位，旧计算完成后自动追赶。

动态 Group 条件还支持 `{ "kind":"group", "groupId":"<uuid>", "op":"member_of" }` 与
`not_member_of`，可单独使用或嵌入现有 AND/OR。只能引用同租户、同 assetContext、已获授权的组；
静态组仍只支持 endpoint。创建与保存拒绝自引用、循环、超过 16 层的依赖和超预算图遍历。
组引用按对象身份求值，Unknown/Conflict 或来源全集外的对象不能因否定而成为成员。
每次计算固定来源定义、成员语义、权限坐标及不可变结果；来源尚未完成时等待，变化后重算。
详情返回 freshness，结果页返回 sources 来源坐标；过期结果的 current 为 false，历史证据仍可读取。
字段、注册、关联或来源权限失效也会使嵌套组及其 Scope/Policy/Compliance 消费失效。

引用选择复用 `GET /api/v1/groups?filter=assetContext==endpoint`；编辑时传
`referenceableFor=<group-id>`，会排除本组、会产生循环和上下文不匹配的候选。保存仍执行事务内复核。

`GET /api/v1/groups/{id}/references?kind&relation&limit&cursor` 查询当前依赖。
kind 为 `group|scope|policy|compliance_rule`，省略时查询获授权类别；relation 为
`direct|indirect|all`，默认 all。查询覆盖嵌套组、Scope 的 target/limitation/exclusion、
策略主范围与软件灰度范围，以及合规规则。每项按来源对象及直接/间接关系归并，返回角色和
确定性代表路径，分别展示生命周期、计算新鲜度、当前有效性及删除阻塞；代表路径不枚举全部路径。
items 经过当前权限过滤，空列表不能作为删除许可；deletionBlocked 包括不可见的当前引用，
但不透露其身份。显式查询无权类别返回 403，根组不存在返回 404。
游标绑定租户、根组、筛选、当前权限及依赖视图；相关定义或展示状态变化返回 409，需要从首页重查。

删除在原写事务内复核所有当前引用。停用的合规规则和保留的 Scope 引用同样阻止删除；
先编辑来源移除引用再删除，历史版本不阻塞。Scope 删除也检查策略主范围与软件灰度阶段引用。
规则写入、删除及重试沿用 operationId/expectedRevision；提交未知时重试原身份和原请求。

例如向 `POST /api/v1/groups/22222222-2222-4222-8222-222222222222` 保存纯组规则：

```json
{
  "operationId": "33333333-3333-4333-8333-333333333333",
  "expectedRevision": 0,
  "input": {
    "action": "create",
    "assetContext": "endpoint",
    "presentation": { "name": "来源组成员", "description": "" },
    "criteria": {
      "selector": { "kind": "device" },
      "quantifier": "one",
      "criteria": { "kind": "group", "groupId": "11111111-1111-4111-8111-111111111111", "op": "member_of" }
    }
  }
}
```

写入返回任务身份及 statusUrl。等待任务完成后，读取
`GET /api/v1/groups/{id}/results/{task}/members?limit=64`，结果页结构如下。
`memberSet` 是来源的不可变结果身份；其余坐标描述本次计算使用的定义、成员语义和授权。

```json
{
  "result": "33333333-3333-4333-8333-333333333333",
  "group": "22222222-2222-4222-8222-222222222222",
  "current": true,
  "sources": [{
    "group": "11111111-1111-4111-8111-111111111111",
    "coordinates": {
      "definitionVersion": 1, "memberVersion": 1, "authorityVersion": 0,
      "memberSet": "44444444-4444-4444-8444-444444444444", "assetContext": "endpoint"
    }
  }],
  "totalObjects": 1, "totalMembers": 1,
  "page": { "kind": "members", "items": [{ "kind": "endpoint", "id": "device-1" }] },
  "nextCursor": null
}
```

对来源组查询 `GET /api/v1/groups/11111111-1111-4111-8111-111111111111/references?relation=all&limit=64`：

```json
{
  "items": [{
    "source": { "kind": "group", "id": "22222222-2222-4222-8222-222222222222" },
    "revision": 1, "relation": "direct", "roles": ["member_of"],
    "via": [
      { "kind": "group", "id": "11111111-1111-4111-8111-111111111111" },
      { "kind": "group", "id": "22222222-2222-4222-8222-222222222222" }
    ],
    "lifecycleState": "active", "freshness": "current", "effective": true, "blocksDeletion": true
  }],
  "nextCursor": null, "deletionBlocked": true
}
```

有 nextCursor 时将原值传入同一查询的 cursor；409 后丢弃旧游标，从首页重查。
组引用保存除 GroupWrite 及全设备 InventoryRead 外还要求 GroupRead，并重新验证引用链的敏感字段权限。
`POST /api/v1/groups/{id}/previews` 使用 `{operationId, expectedRevision, input:{}}`；
预览结果沿用同一 sources 证据和分页结构，current 为 false，不发布正式成员。

编辑 revision、计算发布版本、成员语义 memberVersion 各自独立。无差分重算不改变编辑 CAS 或成员语义版本。Scope 也分别记录定义、计算与目标语义版本；持续匹配设备保留入组坐标，退出后重入取得新坐标。历史结果不会被新事实改写。

Scope 结果页必须指定 `channel=agent|mdm`，游标绑定该通道。每个来源先归一到选定的原始通道，再进行并集、限制与排除；显式终端排除也阻断关联组映射出的同一终端，直接终端来源不会扩展到关联端。Scope 的 `limitations:null` 表示不限制，空数组表示没有匹配限制。Unknown 目标、限制或排除依据会留下逐设备阻断原因；Unknown 排除不能当作“不属于排除组”。来源尚未发布、规则不一致或水位落后时，所有执行消费者通过同一个准入合同阻止新执行。

脚本和软件 Policy 在 Agent 签入时按当前 Scope 与执行条件受理；软件灰度还受管理员配置的阶段范围、时间与可选门槛约束。配置型 Policy 自动核对变化设备并通过 MDM 交付。没有预览→保存 Plan→人工执行链路。配置型不接受脚本频率、触发器或参数。定义和示例见 [企业任务](enterprise-tasks.md)。

AgentCollection Policy 可在任务签名配置前保存并冻结已验证的内容，使基础初始化先于通道设置完成。保存不表示可执行：预览仍要求当前进程加载签名器，实际领取还会核验当前签名权威及设备信任。后续配置签名器后沿用原策略，无需重新发布。

后台任务返回稳定 task 身份；冲突导致替代任务时，状态返回 replacement_task。结果页的 nextCursor 原样续读，不能用固定前 N 台设备代替分页。Group/Scope 任务与派生结果除管理权限外还要求全设备 inventory_read，每页重验。

已发布策略归组织持有，浏览器会话退出或过期不删除分配。来源读授权和动作所需授权撤回会阻止新副作用；既有任务与结果保留原始归属。停用或修改分配需要当前管理员授权。命令失败、命令到期与持续分配状态分别保存；缺少注册或能力不会删除配置分配。脚本 Unknown 不自动重试，退出不虚构副作用撤销。

通道接入使用 `ensure_agent_installed` 与 `request_mdm_enrollment` 两个独立 Action。当前来源注册世代的明确安装/注册观察经动态 Group 和 Scope 触发；Unknown、来源失败和其它组织冲突都不视为缺失，也不用最后连接时间或任意 TTL 推断缺失。发布后保留实际 SoftwareDeploy/Enrollment 授权依据并在执行时重验；浏览器会话退出不撤回分配，权限撤回会阻止新副作用。两端拥有独立 DeviceId、注册、数据与策略，详见[企业任务](enterprise-tasks.md)。

策略分配使用 `GET /api/v1/policies/{id}/assignments`，返回 typed object、channel、availability、reason、可选原始 target、来源证据和执行记录身份。缺失通道只形成 unavailable 分配，不创建操作、尝试或 outbox；数据、通道和关联变更通过既有自动任务重算，通道可用后恢复。Agent 动作仅使用 Agent，配置、原生采集及安装 Agent 仅使用 MDM。派发前重新验证冻结来源，派发后的结果仍属于原任务的终端和注册世代。Compliance 只接受 endpoint 组。

本次契约为新装切换，没有旧 DTO、缺省 assetContext 或 `/policies/{id}/devices` 路由。rss-web 需独立完成 Group/Scope/assignment 契约切换后才能联合发布。

Scope 在发布固定结果前按目标通道完成集合运算，并持久化原始 DeviceId、注册世代与进入坐标。连续成员保留进入坐标；任何已发布的退出后重入都产生新坐标，即使 assignment 后台尚未处理退出。软件灰度统计由现有恢复 worker 按固定结果分批计算并保存游标，结果与能力更新按设备增量刷新，通道集合不变时保留分母。查询返回阶段 `ready` 与 `asOf`；输入过期或计算未完成时统计不可用于打开成功率门禁。

## Windows 恢复凭据策略

`action.kind=credential` 使用现有 Scope、schedule、frequency、runLifetimeSeconds 和显式重执行入口，不依赖虚构 Resource 或独立调度器。指定 Windows `architecture` 及闭合 `operation`：`collect_bitlocker`、`rotate_bitlocker`、`verify_bitlocker`、`rotate_local_administrator`、`verify_local_administrator`。卷操作绑定稳定卷 ID/protector ID，账户操作绑定 SID。安全材料操作使用 `security_operate`，本地账户操作使用 `account_write`；策略发布仍遵循普通 Policy 权限。

只有声明 `credentials.windows.v1` 的受管 Agent 才能领取。RSS 管理账户与微软 LAPS 排他，不读取未知旧密码。轮换先托管新材料，收到持久接收确认后才清理明确替换的旧 protector；Unknown 保留原操作与材料，不自动重新生成。独立验证可核对已有候选材料，解除已确认操作的恢复阻塞。该策略不发布到自助目录。

## 通过 Policy 解除全部管理

`action.kind=unmanage_device` 不引用 Resource，`runLifetimeSeconds` 范围为 60–604800。
默认手动，管理员通过既有 `/policies/{id}/reruns` 显式执行；也可配置日历调度。
不支持签入／注册触发和 Self Service。发布、执行除了 PolicyWrite 还要求
`device_unmanage`；该授权独立于普通策略编辑权限。

退管以完整设备为目标：选择已确认关联的任一端会纳入两端；任一端命中排除即阻止接受。
接受时保存退出意图和原始注册快照，同时停止普通任务和互注册授权。重叠策略或重复执行
复用已接受意图；随后移出 Scope、停用策略或动态组变化不会取消清理。
设备离线、Agent 崩溃或 Profile 消失只改变通道事实，不产生退出意图。

分配查询返回 `channel:null`、`target:null` 和 `operationIds`；通过
`GET /api/v1/device-retirements/{id}` 查看各通道的清理阶段与证据。
配置和软件使用原安装合同清理，仅处理产品管理效果。缺少移除能力、失败、离线或回执
丢失保留待处理／未知结果，不假定卸载成功。Agent 必须支持 `device.unmanage.v1`，
退出任务签名绑定原安装注册、Policy、退出操作和投递尝试。

`POST /api/v1/device-retirements/{id}/force-revoke` 接收 `{operationId,reason}`，
要求 `device_unmanage` 并检查目标权限；它请求最终撤权，不证明设备已卸载。
紧急凭据撤销仍是独立操作，不产生已成功清理设备的结论。

`POST /api/v1/device-views/{kind}/{id}/asset-state` 接收
`{operationId,state:active|archived|deleted}`，要求 InventoryAssign。
归档允许退出中的资产；软删除要求所有注册已失效。列表默认只显示 active，
可用 `assetState` 查询归档或删除的资产，显式详情及审计历史保留。
恢复为 active 不恢复凭据、旧任务或互注册授权。

完成退管后，管理员创建新的 MDM 注册请求才能重新授权该端；Agent 使用新 CSR 请求，
再通过 `POST /api/v1/agent-requests/{id}/reenroll/{device}` 和 `{operationId}`
将其授权给原资产。两种方式都检查 Enrollment 权限并作废旧注册授权。
新注册具有独立身份；普通责任人或策略调整无需重注册。

## 展示字段与执行身份

管理写入提交完整对象并校验 revision；编辑者必须保留读取到的未知展示 key，省略表示删除。
SelfService 的 displayName、description、category、keywords、prerequisites、sideEffects 位于
`presentation`，access、published、allowAi、riskLevel 仍为控制字段。Group 的 name/description、
Compliance 的 name 同样位于各自 presentation。展示修订可审计，但不生成 Policy 执行版本、
Group 成员版本或新的资源制品。SelfService 仍绑定当前 policyRevision 与精确调用输入，
文案更新后须重新读取并确认；没有独立的确认文案存证服务。

Resource 通过现有写入口的 `action: "present"` 和完整 `presentation` 修改对象展示，沿用
operationId/expectedRevision；详情和目录返回 presentation。软件版本详情同时返回
presentation/resourceRevision，展示只从 Resource 读取。原生软件发布文案是冻结发布材料，
由完整材料摘要绑定，修改目录展示不会改写已发布 Winget/Brew 制品。

用户属性定义目录使用相同查询参数，返回 `items/nextCursor/sources`，保留 fieldId 身份；
`sources` 是当前来源可用性元数据，不参与字段投影。列表默认不返回已删除定义。
