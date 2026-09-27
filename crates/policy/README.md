# rss-mdm-policy

统一 Policy 的纯合同与确定性决策。执行型和配置型通过闭合 Rust/JSON 变体表达；配置型不能携带脚本触发、频率、参数或窗口。Resource 与 Scope 都是 opaque 引用，本 crate 不读取其它业务的数据。

`Policy::apply` 只推进配置 CAS。资源/执行语义变化才产生新版本；启停和目标变化保留执行版本。`Definition::semantic` 提供稳定内容坐标。`schedule` 在显式时间和设备身份输入上计算期限、迟到、抖动、跨午夜及 DST，不创建任务或持有调度进度。

本 crate 不持有授权、Group/Scope 成员、数据库、HTTP、Operation、Run、Attempt、执行进度或设备效果。实际受理与事实归执行 owner；存储见 `rss-mdm-policy-postgres`。旧 Plan/Evaluation、ExecutionFacts 和独立审批生命周期已删除。
