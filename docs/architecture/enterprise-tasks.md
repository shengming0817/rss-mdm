# 企业任务设计

## 决定与理由

Resource.Script 同时持有脚本和采集模板不可变版本，避免重复 CRUD/version owner。ActionRun 与状态型命令共享可靠投递、事务与恢复设施，但执行进度和设备效果分开：退出码零不能生成 Applied。

计划冻结版本、参数、目标与批准；生产、领取、下载和启动许可重新验证当前权限与注册世代。签名绑定可信 tenant/device/registration/generation/platform/architecture/task/attempt/permit 及 keyId，防止跨上下文重放。参数仅字面量 argv/环境变量传递，平台和身份不隐式降级。

调度 occurrence 是持久业务身份。容量阻塞保留原坐标，不推进扫描游标；重试仍遵守窗口、misfire 与截止规则，成功后只推进到原坐标。这样重启或暂时容量不足不会跳过任务，也不会把旧触发伪装成新触发。开始后结果未知不得自动重执行副作用。

不可变制品先核验长度/摘要再原子落盘，同租户文件锁串行化上传与残留清理。task/attempt 已足以提供下载授权，不另建 grant 状态机；摘要与完整结果分开读取，避免列表泄露输出。

采集字段使用独立 dataset/coverage/object，避免不同模板快照互相删除事实。无效、部分、截断或迟到结果只留下质量证据，保留最后已知值及其来源时间，不引入字段 TTL。定义和操作见 [企业任务指南](../guides/enterprise-tasks.md)，安装基线见 [运维](../deployment/operations.md)。

## 来源

- jsonschema `c6ee21efc29083422e466aceb2a15bf1e50c83b3`，`crates/jsonschema/src/options.rs`。
- ring `2723abbca9e83347d82b056d5b239c6604f786df`，`src/signature.rs`。
- Jiff `4100a7c71125b9523029566d1d18f8b227ecd18c`，`crates/jiff/src/tz/ambiguous.rs`。
- osquery `1889d51f0d1680672016a801e9d65799eb5fc5dc`，`osquery/config/packs.cpp`、`specs/utility/osquery_info.table`。
