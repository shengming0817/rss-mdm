# rss-mdm-resource-postgres

不可变版本与生命周期；归档仅借用事务，由 app 原子保护引用。

Store 通过同一宿主 `Arc<PgRuntime>` 接入，宿主关闭 runtime。使用本包 `core` 中的对应核心类型，TenantId / Timepoint 来自 canonical RSS owner。构造时校验本包 migration 的精确 catalog/权限；独立运行角色无 DDL、owner、superuser 或 BYPASSRLS。

`*_in` 校验 runtime owner/tenant，返回两层结果；业务拒绝必须处理，PG 错误须传播给外层以回滚。状态、原请求/回执和 Outbox 同事务；CommitUnknown / RollbackFailed 保留原请求身份，重连后查 operation 或精确重放，不生成新身份。序列化只在 adapter，恢复经过摘要、闭合格式及核心验证。

[完整调用、迁移和边界指南](../../docs/guides/202609132008-2388-2389-backend-persistence.md)。

```sh
cargo test --locked -p rss-mdm-resource-postgres
make t2-backend
# 提交后验证默认/关闭默认 feature 的固定 SHA 独立消费者
make backend-consumers
```

参考 SQLx v0.9.0 `sqlx-core/src/transaction.rs` 的提交/回滚不确定语义，复用 RSS 公开事务和 Outbox；不引入新的通用持久化框架。运行记录绑定源码 SHA，T2 不代表产品端侧 T3。
