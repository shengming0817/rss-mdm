# 资产变化与自动分配

固定 AssetCut 与分批不可变结果使计算可恢复，避免跨页长事务与全量复制。

## 行为边界

资产新增、更新、显式删除以及注册/来源变化驱动 Group、Scope、Policy 收敛。
资产字段没有 TTL。每租户、每组和每策略支持百万当前设备；执行历史分页读取，
不以当前设备容量截断历史。暂停/归档沿用核心决策语义。

Policy 持续引用 Scope；成员变化自动建立执行资格或触发原生配置核对。
Agent 在签入时受理自己的 Run，配置型仅对必要差分入队；发布不生成全体设备的周期任务。
执行事实由实际受理和进度的 owner 提供，目标计算不能自行证明执行。

## 引用阻断摘要

Resource 版本、Group 与资产字段的 `/references` 返回直接阻断来源的 `Page`，
只接受 `limit` 与 `cursor`，默认及最大页长为 1,000。它们分别要求目标侧的
`ResourceRead`、`GroupRead`、`InventoryFieldsWrite`，返回同租户最小身份、
角色和支持的解除方式；来源名称、配置与详情继续由来源自身权限保护。
保存查询的身份包含 instance、owner、id，即使属于其他用户也只暴露该坐标。
每页复验目标存在和当前权限，游标绑定目标、主体、权限及页长；不承诺跨页快照。

摘要与写入门禁读取同一引用事实。历史 Policy 版本、软件发布主体及目录记录在停用、
归档或撤回后仍可能保留引用；采集 Profile 归档后释放模板与字段引用。
Policy 独占主 Scope 与阶段 Scope；禁用保持计算和当前依赖，归档或移除阶段退役范围并保留历史。
保存、权限及子路由见[组、范围与 Policy](../guides/groups-scopes-policies.md#policy-范围保存预览与重算)。
Group 的递归影响另由 `/groups/{id}/impacts` 提供，保留全设备库存读取与来源类型权限检查。
空摘要不构成删除或归档授权；写入仍在原锁和事务内复验，真正的引用阻断返回
HTTP 409 `object_referenced`，其他版本、保护或生命周期冲突保持原有错误。

## 唯一职责

- Inventory 保存字段版本历史；Registration 保存注册与来源版本历史。
- 事实事务保存唯一事件身份、资产历史代次和顶层事务号。事件编号只用于身份和窗口内扫描，
  不表示提交顺序；普通写方只读当前代次，不更新公共计数行。
- 每个资产事实通过 RSS 公开 SQL Outbox 接口追加单份无分区消息，事实、历史与消息同事务。
  消息携带原始租户、事实身份、注册/来源世代、变化字段和资格重验范围，不携带资产值或凭据秘密。
  采集失败、证据删除和来源撤销分别表达；采集接收不证明库存投影已完成，内部交付确认不产生规则变化。
  App 的固定同库投影只原子登记 Group、Compliance、Scope 和 Policy 配置输入的持久 wake；
  对象关系事实由 Device 发布，只唤醒其实际消费者。投影不读取业务表、求值或推进业务检查点。
  源消息、Inbox 与全部 wake 一起结算；业务 owner 随后独立消费，通知仅加速领取。
- AssetCut 绑定租户、历史代次和 PostgreSQL snapshot。通过既有只读入口捕获已提交事实，
  释放读取连接后才进入业务写事务。历史读取先按切面过滤，再选同对象最新版本；
  同对象业务锁保证版本顺序。自身未提交写入不进入切面，需要新事实的计算由原事务登记持久任务，提交后捕获输入。
- Inventory 的 Group、资产查询、Compliance 任务和独立 Scope 任务直接通过 RSS 公共 messaging 能力原子保存并唤醒；Device 与 Software 分别拥有所属设备来源变化扫描。
  RSS 独占 claim、lease、重试及恢复；产品不直接调用组件私有 SQL。
  新输入通过各 owner 的持久检查点合并；已运行的计算保留检查点，完成后追赶较新输入。
  Scope 计算冲突自动产生可查询的替代任务；临时未完成的来源不能授权新执行。
- Inventory 的 Group 和独立 Scope 各自保存不可变分批结果，发起用例的能力组合跨 owner 事务和授权。
  有界求值复用原决策逻辑；页输入和完整结果使用不同类型。
- ingress 每批冻结最多 1,000 条已提交变更。Group owner 通过反向索引按设备查询最新
  已发布成员，逐设备最多取 33 个候选组再合并；Inventory 维护字段→组索引和 Group 任务引用。
  已发布结果覆盖当前固定切面的相关变化与规则时跳过重算；待处理任务用冻结的定义修订去重。
  已有任务不能确认其输入之外的变化：Group/Scope 记录合并请求的代次与原事务坐标，
  固定 AssetCut 只覆盖该快照可见的请求。新请求不在旧切面内时保守保留需求，发布及传播收尾
  同事务登记唯一后继；静态成员编辑也追赶，后继不重复应用原 patch。失败沿原 RSS 暂停语义处理。
- 动态 Group 在规则不变时，按有界输入批次只求值受相关字段或身份变化影响的设备。
  稀疏计算保留前一完整基线，历史结果仍按其冻结发布序列读取，规则变化必要全算。
- Policy 发布锁定资源版本和目标引用。Scope 是唯一目标 owner；消费者通过同一个
  `scope_admission` 合同判断新鲜度、有效成员和 Unknown 阻断，不另存永久目标副本。

Registration 的 `mdm_access.asset_authority_history` 是按对象版本排序、只追加的授权历史投影；Inventory 的 `mdm_assets.group_fields` 是规则字段依赖索引。二者发布给实际消费者的只读 SQL 合同用于同一事务中的有界联合查询和 `scope_admission`，由各 owner 的安装定义、精确角色权限与 catalog 校验约束；活动注册/凭据的检查及变更必须使用 Registration 的借用事务接口。

Group 的规则、唯一图边索引、图版本、定义遍历和来源坐标由 `group-postgres` 持有；
Inventory 持有定义编辑、正式计算、预览任务及求值检查点。`mdm.groups` reconciler 与
Scope 的 `mdm.scopes` 任务独立，资产及关联关系各有 Group 消费进度，不使用共享 forwarded 标记。

Inventory Group、Compliance、Scope、Software、Device 各自复用原检查点保存
`from_cut / to_cut / event_after` 和必要的 fanout 游标。一次窗口仅处理
`visible(to_cut) && !visible(from_cut)`，每次有界扫描事件和目标；下游效果、持久待办与游标原子提交。
差集耗尽才将 from_cut 推进至 to_cut，中断继续原窗口；低编号晚提交事件进入后续差集。
不保存重复事件集合或共享 ACK。新建 Group/Scope 由自身初始化任务计算，不依赖旧 fanout。
当前授权和执行资格核对当前事实及切面外相关变化，不等待后台检查点追上。

资产查询与 Compliance 分别使用 `mdm.asset-queries`、`mdm.compliance`，由 App 直接装配。
查询输入、进度与统计归 `mdm_assets.asset_query_runs`；合规任务、结果、终态和库存消费进度归
`mdm_compliance`，历史不再关联中央任务表。Group、Query、Compliance 各自持久化求值检查点，
Inventory 只共享有界数组读取与求值算法。检查点、结果和终态在原事务中提交。
查询完成后的结果不可变；当前授权继续适用，新上报不改变旧结果分页。Compliance 独立消费
两个切面之间的已提交库存变化，Group 失效待办在 Group 原事务写入；其当前发布要求精确匹配成员版本，
与冻结成员结果仍可读取的语义分别检查。

Group 发布、删除、定义或 authority-only 变化在原业务事务保存稳定身份的 GroupChanged。
固定 `mdm-scope-group-changes` 消费组通过 RSS 同库投影，在同一事务提交 Inbox、Scope
持久待办和源 Outbox 结算；Scope 后续每批影响展开与重算请求同事务保存。该通道仅供 Scope，
Group 内部依赖传播和 Compliance 唤醒仍各自在业务事务中完成。
事件计数与成员存储使用相同的非负 bigint 范围，百万设备容量目标不作为事件拒绝阈值。

Scope 的定义、来源快照、运行、集合结果、任务与消费进度归 `scope-postgres` 的 `mdm_scope`。
定义与结果版本直接读取权威记录，设备 authority 读取 Registration，不维护通用 `source_heads` 副本。
Scope 独立消费 Group 通知及设备来源变化，使用自己的检查点；Device 与 Software 各自持有 device_source_dispatch 与设备唤醒处理。两者各自推进，设备执行唤醒的进度不会阻塞 Scope。

Scope 拥有按 run 绑定的通道投影、分页进度、通道语义版本及 entry 连续性。两侧可分批暂存，
最终在同一实际事务重验定义和前一结果，发布 Scope head 与完整通道投影，并登记一项 Policy 后续任务。
Compliance 用 Group 的定义语义版本与三值成员版本判定冻结证据是否仍有效，
用最新完整 Group 计算的输入切面检查是否还存在未覆盖事实。展示修订和无差分计算不使
冻结结果失效；规则语义变化即使成员相同也传播需求。

Scope 任务随后完成；Policy 在原事务保存 work 并直接 wake 对应 job/event，没有 inputs 转发任务或 forwarded 状态。
Policy 自己持有传播游标、重试和分配任务，不反向阻塞 Scope 的完成或恢复；started 仅由实际受 claim 保护的执行写入。
唯一有效结果指针由 Scope 持有，尚未发布的投影不能参与准入。

AssetCut 作为值保存在原输入、任务和固定历史游标中。当前格式逻辑恢复在停止所有 writer 的流程内，
数据库恢复后原子建立新的资产历史代次，同一恢复操作重试复用该代次；同时校验事件分配器不复用身份。
同代次事件按保存的 snapshot 判断，祖先代次是恢复基线，后继或无关代次不可见。
旧切面、回执和未完成任务保留原输入；新切面包含恢复基线与恢复后已提交事实。

## 发布与失效

每轮固定 AssetCut 及定义版本。默认页上限为 1,000 对象、16 MiB，并继续执行
谓词访问与解释预算。页数据、内容指纹和游标同事务保存；原页可恢复重放。
成员差分提前分批计算。最终事务只发布指针、引用版本、摘要事件与后续触发，
不复制百万行，不跨页持锁。

Group 的编辑 CAS、计算发布序列和成员语义版本分别保存。无差分重算不修改编辑 CAS 或 memberVersion；身份变化独立使来源失效。Scope 同样区分定义、计算和目标语义版本，连续匹配保留入组身份，退出后重入产生新身份。
读取 fresh 不能只看本地定义 revision，也不能等待逐策略循环后才失效。
Policy 草稿预览只读取当前结果，不发布 Scope、不保存正式 Policy、不创建 Run 或原生命令。
脚本发布、草稿预览和即时执行共享 Resource 的精确变体准备：参数、平台适用性、制品预算和 SQL 内容身份由同一合同校验。
Content 验证实际字节；各入口在事务中重新读取活动资源版本并核对完整制品身份。
预览不注册采集定义；发布和即时执行在写入事务中冻结已检查的脚本及必要采集定义。
Device 保留 immutable object cut、对象版本和发布序列。完整历史结果与当前资格分别判断，completed 不证明现在仍有效。
Scope、计划期限、当前授权和设备执行资格仍由各消费用例持有，实际受理及交付继续重验。

## 失败诊断与恢复

本链 inputs 在检查点收敛后真正 Converged，不定期重新扫描资产历史。启动和监听重连检查
RSS 持久待办，投影结合通知、next_wakeup 和最长 60 秒的恢复检查继续推进。
正常空闲只扫描调度/投递待办，不以启动无条件 wake 制造业务输入；首次成功调度扫描建立运行观测；输入健康另读 owner 检查点上的持久失败事实，
不会清除已有持久失败。Policy schedules、配置 relay、命令恢复及 RSS 租约/失败重试保持各自职责。
切面差集在单条语句内复用已校验的 AssetCut 上下文，并直接使用外层事件的 epoch/XID 判断可见性。


RSS 作出 Suspended 决定后，产品先在 `messaging::protect` 中保存任务失败
`automation_suspended` 和审计，再由 RSS 完成调度状态。业务或审计事务失败时不暂停
RSS 目标；提交未知沿原 claim/任务身份恢复，不把未知结果当作回滚。
计算竞争由替代任务自动接续；依赖暂时不可用时保留诊断和持久检查点。
Group、Scope、Query 和 Compliance runner 分别保留有界扫描与尝试失败观察，汇总到现有 Automation 诊断。成功扫描不清除尝试失败；普通任务只有同一目标的成功结算清除其记录。Group、Scope、Compliance 的 inputs 失败在 RSS claim 保护下写入各自检查点；唤醒和重启均不清除，成功推进后的结算才清除。所有实例读取该持久状态，并清理已经恢复的本地 inputs 失败观察。观察超过保留预算时显式标记截断，不以无记录冒充恢复。

Device/Software 与 Policy configuration 的输入终止尝试通过相同 claim 保护，在业务检查点保存唯一持久失败诊断和审计，
输出 `mdm_automation_terminal_attempt`；所有实例的 readiness 都检查此诊断，不只依赖本地任务是否运行。
它不是 RSS 调度状态副本：RSS 可能保留较新的 wake；只要新的有效 claim 成功提交检查点进度，
或受 claim 保护确认已收敛，才在同一事务中清除诊断。恢复依赖后，由新的事实或既有恢复入口产生有效 claim；
普通启动不会重新唤醒已暂停输入、清除诊断或提前恢复健康。无新 wake 时遵循 RSS 的暂停决定，不轮询清零重试次数。
诊断仅含任务身份和失败次数，不含资产值；游标密钥不进入日志或响应。

后台固定输入中的损坏时间、游标、规则、事实或编码按内部存储失败处理，由 RSS 恢复策略处理，
不把已接受任务误记为客户端 `invalid_input`。正常入口的非法输入仍按原请求错误返回。
借用事务参考：[SQLx v0.9.0 transaction.rs](https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-core/src/transaction.rs)。

操作与分页见 [组、范围与 Policy](../guides/groups-scopes-policies.md)。容量目标须由独立性能验证给出证据，功能边界测试不作规模证明。

业务回执的 operationId 以能力 owner、租户和已验证主体为作用域；规划、资产、资源目录与软件发布的审计事件键使用同一 owner namespace。同一作用域内的重复请求恢复原回执，复用标识但改变请求返回冲突；不同主体或能力的操作不会混用回执。
