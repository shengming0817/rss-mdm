# Agent V2 与企业任务升级

唯一允许升级的旧基线为 `a83f7876289f15f294940964df69579d62126557` 的完整 39 单元 name+SHA-256 ledger。空库可安装，当前完整 45 单元 ledger 可重放；其他前缀、缺失、未知、修改摘要、未完成单元均拒绝。基线清单固定在 `crates/app/src/migration/baseline-a83f7876.json`。历史 SQL 不改写。

1. 在旧版本正常运行时排空 Agent 待投递报告，撤销旧 Agent registration 及 credential。V2 只接受有序 capability 集合 `["inventory.basic.v2"]` 或 `["inventory.basic.v2","task.execute.v2"]`；仅需要库存报告的 Agent 使用前者，需要企业任务的 Agent 必须显式使用后者。
2. 检查旧 Script 版本。旧声明不含完整执行接口，安装器拒绝推断默认值或迁移它；必须显式重新建模和规划数据迁移，不能删除历史记录来绕过检查。
3. 停止旧服务，备份数据库和本地制品，使用受控 owner 执行 migrate。新增的 nullable `mdm_commands.action_plans.blocked_at` 保存容量阻塞的原 occurrence 坐标；升级不从 `scan_at` 推断或回填它。预检遍历全部已安装租户，RLS 不会隐藏未清理状态。
4. 部署新服务和可信签名配置，通过新的 Enrollment 授权重新注册 Agent。每个 tenant 制品目录必须允许服务创建并锁定 `.upload.lock`；启动会在持有该跨实例独占锁时删除精确命名的 `.upload-<canonical hyphenated UUID>` 残留普通文件，失败则以 CommandStorage 阻止启动。旧凭据即使数据库状态误留 active，也不能用于 V2；V2 是未发布候选，本次直接替换 capability 和 result shape，不保留候选兼容解码，也没有 V1 路由或双协议降级。
5. Inventory 使用 inventory-v3 从原 Observation journal 重放。原事实、历史和基础报告保留，重放完成前不把视图完整性当作已确认。

数据库版本、服务代码和 Agent wire 必须整体切换。失败前置检查不会删除账本、自动撤销身份或清空业务证据。完成迁移后的回退使用成套数据库/制品备份和对应旧服务，不能仅降级二进制。
