# 组、范围与 Policy

Group 持有成员求值；Scope 组合目标并集、限制并集和排除并集；Policy 持续引用 Scope 并分配闭合 Action；资源绑定位于需要资源的 Action 内。管理入口是 `/api/v2`，资源入口是 `/api/v3`。写入带 operationId、expectedRevision、input；提交未知时重试原身份和原文档。

目录读取使用 `GET /api/v2/groups`、`GET /api/v2/scopes`、`GET /api/v2/policies` 和
`GET /api/v3/resources`，返回 `items/nextCursor`。统一支持 `limit`（默认 64、1–1000）、
`after` 和 `descending`，按 ID 排序；`nextCursor` 作为下次请求的 `after`。
Group 可筛选 `kind/deleted/name`，Scope 可筛选 `deleted/ready`，Policy 可筛选
`enabled/action/scope/resource`，Resource 可筛选 `kind/active`。删除对象默认不进入 Group/Scope 目录。
无名称的 Scope、Policy、Resource 使用既有 ID，不新增名称或另一套对象模型。
权限沿用原 owner；Group 成员摘要仍要求全设备 `inventory_read`。翻页不冻结权限或业务状态。

动态组创建或规则变化自动计算，相关事实按字段和设备增量求值，必要时全算。静态组使用 add/remove。预览保存独立计算结果，不发布正式成员、不产生执行。计算检查点固定输入水位并分页恢复；新输入合并到待处理水位，旧计算完成后自动追赶。

编辑 revision、计算发布版本、成员语义 memberVersion 各自独立。无差分重算不改变编辑 CAS 或成员语义版本。Scope 也分别记录定义、计算与目标语义版本；持续匹配设备保留入组坐标，退出后重入取得新坐标。历史结果不会被新事实改写。

Scope 的 `limitations:null` 表示不限制，空数组表示没有匹配限制。Unknown 目标、限制或排除依据会留下逐设备阻断原因；Unknown 排除不能当作“不属于排除组”。来源尚未发布、规则不一致或水位落后时，所有执行消费者通过同一个准入合同阻止新执行。

脚本和软件 Policy 在 Agent 签入时按当前 Scope 与执行条件受理；软件灰度还受管理员配置的阶段范围、时间与可选门槛约束。配置型 Policy 自动核对变化设备并通过 MDM 交付。没有预览→保存 Plan→人工执行链路。配置型不接受脚本频率、触发器或参数。定义和示例见 [企业任务](enterprise-tasks.md)。

后台任务返回稳定 task 身份；冲突导致替代任务时，状态返回 replacement_task。结果页的 nextCursor 原样续读，不能用固定前 N 台设备代替分页。Group/Scope 任务与派生结果除管理权限外还要求全设备 inventory_read，每页重验。

已发布策略归组织持有，发布者离职或会话过期不会使策略失效。停用或修改分配需要当前管理员授权。命令失败、命令到期与持续分配状态分别保存；缺少注册或能力不会删除配置分配。脚本 Unknown 不自动重试，退出不虚构副作用撤销。

通道接入使用 `ensure_agent_installed` 与 `request_mdm_enrollment` 两个独立 Action。当前来源注册世代的明确安装/注册观察经动态 Group 和 Scope 触发；Unknown、来源失败和其它组织冲突都不视为缺失，也不用最后连接时间或任意 TTL 推断缺失。发布后保留实际 SoftwareDeploy/Enrollment 授权依据并在执行时重验；浏览器会话退出不撤回分配，权限撤回会阻止新副作用。两端拥有独立 DeviceId、注册、数据与策略，详见[企业任务](enterprise-tasks.md)。
