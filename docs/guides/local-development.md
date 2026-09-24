# 本地开发

本仓独立维护 Cargo workspace。工具链、依赖和命令分别以 `rust-toolchain.toml`、`Cargo.toml` / `Cargo.lock`、[Makefile](../../Makefile) 为准。先阅读 [协作入口](../../AGENTS.md) 与 [验证规则](../rules/verification-scope.md)。

```sh
cargo build --locked
make test
make t2
make ci-plan CI_BASE=origin/develop
```

`make t2` 创建真实 PostgreSQL 依赖；缺少 Docker 或必要工具时必须处理失败。编辑循环选择受影响测试，最终检查不要求先提交源码。需要 worktree 独立产物时显式设置 `CARGO_TARGET_DIR="$PWD/target"`。

## Inventory 调试

示例程序使用受控操作员提供的 `DATABASE_URL`、`PG_CA_FILE`、`MDM_SCOPE_FILE`；scope 文件不是来自请求的认证声明。输入格式见 [fixtures](../../fixtures)，示例入口见 [examples](../../crates/examples)。

```sh
cargo run --locked -p rss-mdm-examples -- ingest-fixture fixtures/snapshot.json
cargo run --locked -p rss-mdm-examples -- project
cargo run --locked -p rss-mdm-examples -- inspect snapshot-1
```

持久 receipt 仅证明报告接收，资产查询须另看投影状态。完整 Snapshot 只替换其明确的 scope/coverage，Partial/Failed 不清空最后完整事实；Delta 需要连续来源序列。提交未知时保留原报告和操作身份查询、精确重放，暂时查不到不能证明回滚。

产品运行和初始化使用 [安装指南](../deployment/installation.md)，不以示例 CLI 代替生产入口。
