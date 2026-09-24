# 组、范围与持久计划

Group 解释资产条件并持有成员，Scope 组合组与设备来源，Policy 决定意图。应用负责真实权限、来源、跨 owner 引用和事务审计。类型/API 由各 crate rustdoc 持有，资产字典见 [资产指南](assets.md)，持久计算理由见 [资产自动化设计](../architecture/asset-automation.md)。

## 从规则到计划

1. 用 Group create 创建静态组（criteria=null）或动态规则；静态 members 使用 add/remove，不能覆盖动态成员。
2. 动态条件复用资产类型系统；仅 Match 入组，合法 Unknown 不入组，不完整输入不发布结果。preview 不发布成员，recompute 才更新持久成员。
3. Scope 计算目标并集 ∩ 限制并集 − 排除并集。limitations=null 表示不限制，[] 表示空限制；设备和组来源都绑定明确版本。
4. Policy activate 绑定不可变资源版本。preview 冻结已发布 Scope、策略版本与引用令牌；任务完成后 save 重新核对当前权限、CAS 和来源版本，过期候选返回冲突，不偷偷重算。

管理入口使用 `/api/v2`，资源使用 `/api/v3`。写入携带 operationId、expectedRevision、input；提交未知重放原请求。异步操作返回 task/statusUrl，完成后按结果入口分页；nextCursor 原样续读，尾页可为空。完整请求形态见 [管理源码](../../crates/app/src/management)。

管理动作权限之外，Group 回执、Group/Scope 任务、三类结果页与计划摘要还要求全设备 inventory_read。每页重验权限，已有游标不能绕过撤权；部分设备范围不能替代租户级组计算。定义获授权提交后，后台作为服务推进，不保存发起人的过期授权快照。

## 版本、事实与引用

每轮计算固定已提交资产水位与定义版本，结果不可变且分页发布。无成员差分不推进 memberVersion；注册身份变化仍使来源引用失效。历史结果不会因新事实或对象删除改写。

Scope/Group 删除与引用新增在同一受控事务中序列化；被当前范围或计划历史引用的对象不能删除。设备撤销是安全动作，不被业务引用阻止，失效设备不能成为新有效目标。

保存计划只安装意图与引用，不预造 Planned、授权或执行事实。真实执行 owner 提供进度和效果；成功不等于效果已核实，取消不等于撤销效果，Unknown 不自动重试。暂停不新增 Apply，归档保留历史并产生所需取消意图；同版本旧执行身份不因重新入组而变化。

自动候选仅跟随最近保存的 Scope，候选不会自动保存或派发。实际设备执行见 [设备操作](device-operations.md)，资源发布见 [资源与软件](resources-and-software.md)。
