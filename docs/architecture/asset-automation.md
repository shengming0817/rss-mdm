# 资产变化与自动分配

固定输入水位与分批不可变结果使计算可恢复，避免跨页长事务与全量复制。

## 行为边界

资产新增、更新、显式删除以及注册/来源变化驱动 Group、Scope、Policy 收敛。
资产字段没有 TTL。每租户、每组和每策略支持百万当前设备；执行历史分页读取，
不以当前设备容量截断历史。暂停/归档沿用核心决策语义。

Policy 持续引用 Scope；成员变化自动建立执行资格或触发原生配置核对。
Agent 在签入时受理自己的 Run，配置型仅对必要差分入队；发布不生成全体设备的周期任务。
执行事实由实际受理和进度的 owner 提供，目标计算不能自行证明执行。

## 唯一职责

- Inventory 保存字段版本历史；Registration 保存注册与来源版本历史。
- 事实事务同时保存提交有序水位和 ingress。租户计数器行锁持续到事务结束，
  普通 sequence 最大值不能代表已提交水位。
- Inventory 的 Group、资产查询和 Compliance 任务直接通过 RSS 公共 messaging 能力原子保存并唤醒；剩余 Flow 任务由其转交器唤醒。
  RSS 独占 claim、lease、重试及恢复；产品不直接调用组件私有 SQL。
  新输入通过持久水位合并；已运行的计算保留检查点，完成后追赶较新输入。
  Scope 计算冲突自动产生可查询的替代任务；临时未完成的来源不能授权新执行。
- Inventory 的 Group 和 Flow 的 Scope 各自保存不可变分批结果，发起用例的能力组合跨 owner 事务和授权。
  有界求值复用原决策逻辑；页输入和完整结果使用不同类型。
- ingress 每批冻结最多 1,000 条已提交变更。Group owner 通过反向索引按设备查询最新
  已发布成员，逐设备最多取 33 个候选组再合并；Inventory 维护字段→组索引和 Group 任务引用。
  已发布结果覆盖当前批次水位与规则时跳过重算；待处理任务用冻结的定义修订去重。
- 动态 Group 在规则不变时，按有界输入批次只求值受相关字段或身份变化影响的设备。
  稀疏计算保留前一完整基线，历史结果仍按其冻结发布序列读取，规则变化必要全算。
- Policy 发布锁定资源版本和目标引用。Scope 是唯一目标 owner；消费者通过同一个
  `scope_admission` 合同判断新鲜度、有效成员和 Unknown 阻断，不另存永久目标副本。

Registration 的 `mdm_access.asset_authority_history` 是提交有序、只追加的授权历史投影；Inventory 的 `mdm_assets.group_fields` 是规则字段依赖索引。二者发布给实际消费者的只读 SQL 合同用于同一事务中的有界联合查询和 `scope_admission`，由各 owner 的安装定义、精确角色权限与 catalog 校验约束；活动注册/凭据的检查及变更必须使用 Registration 的借用事务接口。

Group 的规则、唯一图边索引、图版本、定义遍历和来源坐标由 `group-postgres` 持有；
Inventory 持有定义编辑、正式计算、预览任务及求值检查点。`mdm.groups` reconciler 与
Scope 的原有任务路径独立，资产及关联关系各有 Group 消费进度，不使用共享 forwarded 标记。

资产查询与 Compliance 分别使用 `mdm.asset-queries`、`mdm.compliance`，由 App 直接装配。
查询输入、进度与统计归 `mdm_assets.asset_query_runs`；合规任务、结果、终态和库存消费进度归
`mdm_compliance`，历史不再关联中央任务表。Group、Query、Compliance 各自持久化求值检查点，
Inventory 只共享有界数组读取与求值算法。检查点、结果和终态在原事务中提交。
查询完成后的结果不可变；当前授权继续适用，新上报不改变旧结果分页。Compliance 独立消费
提交有序的库存变化，Group 失效待办在 Group 原事务写入；其当前发布要求精确匹配成员版本，
与冻结成员结果仍可读取的语义分别检查。

Group 发布、删除、定义或 authority-only 变化在原业务事务保存稳定身份的 GroupChanged。
固定 `mdm-scope-group-changes` 消费组通过 RSS 同库投影，在同一事务提交 Inbox、Scope
持久待办和源 Outbox 结算；Scope 后续每批影响展开与重算请求同事务保存。该通道仅供 Scope，
Group 内部依赖传播和 Compliance 唤醒仍各自在业务事务中完成。
事件计数与成员存储使用相同的非负 bigint 范围，百万设备容量目标不作为事件拒绝阈值。

## 发布与失效

每轮固定输入水位及定义版本。默认页上限为 1,000 对象、16 MiB，并继续执行
谓词访问与解释预算。页数据、内容指纹和游标同事务保存；原页可恢复重放。
成员差分提前分批计算。最终事务只发布指针、引用版本、摘要事件与后续触发，
不复制百万行，不跨页持锁。

Group 的编辑 CAS、计算发布序列和成员语义版本分别保存。无差分重算不修改编辑 CAS 或 memberVersion；身份变化独立使来源失效。Scope 同样区分定义、计算和目标语义版本，连续匹配保留入组身份，退出后重入产生新身份。
读取 fresh 不能只看本地定义 revision，也不能等待逐策略循环后才失效。
Policy 草稿预览只读取当前结果，不发布 Scope、不保存正式 Policy、不创建 Run 或原生命令。
脚本发布、草稿预览和即时执行共享 Resource 的精确变体准备：参数、平台适用性、制品预算和 SQL 内容身份由同一合同校验。
Content 验证实际字节；各入口在事务中重新读取活动资源版本并核对完整制品身份。
预览不注册采集定义；发布和即时执行在写入事务中冻结已检查的脚本及必要采集定义。
Scope、计划期限、当前授权和设备执行资格仍由各消费用例持有，实际受理及交付继续重验。

## 失败诊断与恢复

RSS 作出 Suspended 决定后，产品先在 `messaging::protect` 中保存任务失败
`automation_suspended` 和审计，再由 RSS 完成调度状态。业务或审计事务失败时不暂停
RSS 目标；提交未知沿原 claim/任务身份恢复，不把未知结果当作回滚。
计算竞争由替代任务自动接续；依赖暂时不可用时保留诊断和持久检查点。
Group、Query 和 Compliance runner 分别保留有界扫描与尝试失败观察，汇总到现有 Automation 诊断。成功扫描不清除尝试失败；只有同一目标的成功结算清除其记录。观察超过保留预算时显式标记截断，不以无记录冒充恢复。

资产 ingress 的终止尝试通过相同 claim 保护，在业务检查点保存唯一持久失败诊断和审计，
输出 `mdm_automation_terminal_attempt`；所有实例的 readiness 都检查此诊断，不只依赖本地任务是否运行。
它不是 RSS 调度状态副本：RSS 可能保留较新的 wake；只要新的有效 claim 成功提交检查点进度，
或受 claim 保护确认已收敛，才在同一事务中清除诊断。恢复依赖后可重启以重新 wake 已转交输入，
但普通启动不会清除诊断或提前恢复健康。无新 wake 时遵循 RSS 的暂停决定，不轮询清零重试次数。
诊断仅含任务身份和失败次数，不含资产值；游标密钥不进入日志或响应。

后台固定输入中的损坏时间、游标、规则、事实或编码按内部存储失败处理，由 RSS 恢复策略处理，
不把已接受任务误记为客户端 `invalid_input`。正常入口的非法输入仍按原请求错误返回。
借用事务参考：[SQLx v0.9.0 transaction.rs](https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-core/src/transaction.rs)。

操作与分页见 [组、范围与 Policy](../guides/groups-scopes-policies.md)。容量目标须由独立性能验证给出证据，功能边界测试不作规模证明。

业务回执的 operationId 以能力 owner、租户和已验证主体为作用域；规划、资产、资源目录与软件发布的审计事件键使用同一 owner namespace。同一作用域内的重复请求恢复原回执，复用标识但改变请求返回冲突；不同主体或能力的操作不会混用回执。
