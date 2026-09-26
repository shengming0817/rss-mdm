# 本地开发

本仓独立维护 Cargo workspace。工具链、依赖和命令分别以 `rust-toolchain.toml`、`Cargo.toml` / `Cargo.lock`、[Makefile](../../Makefile) 为准。先阅读 [协作入口](../../AGENTS.md) 与 [验证规则](../rules/verification-scope.md)。

```sh
make build
make check
make test
make t2
make ci-plan CI_BASE=origin/develop
```

`make t2` 创建真实 PostgreSQL 依赖；缺少 Docker 或必要工具时必须处理失败。编辑循环选择受影响测试，最终检查不要求先提交源码。

## 构建槽位与缓存

Make 的 build/check/test、CI 和定向 T2 入口由 [启动器](../../hack/build_run.py) 管理：默认四个槽，
每次完整命令独占 worktree 和 target，子进程继承租约。同 worktree 优先复用空闲槽；槽换属时清理旧产物。
槽满、worktree 或目标目录已占用时立即失败，待原运行退出后重试。槽数不限制每个 Cargo 的编译线程数。

| 配置 | 行为 |
| --- | --- |
| `MDM_TARGET_POOL_N` | 默认 `4`；正整数调整槽数，`0/off` 改用当前 worktree 的 target |
| `MDM_TARGET_POOL_ROOT` | 默认 `~/.cache/rss-mdm-cargo-target-pool`，必须是空目录或已标记的专用池 |
| `CARGO_TARGET_DIR` | 显式目录绕过池分配，仍须取得独占锁；不能与显式正数槽配置共用，也不能指向池内部 |
| `MDM_COMPILER_CACHE` | `auto` 默认，缓存不可用时直接编译；`on` 要求缓存可用；`off` 禁用自动缓存 |

例如定向验证使用同一个启动器，不直接运行正式 CI/T2 脚本；这些脚本在缺失有效租约时会拒绝执行。

```sh
python3 hack/build_run.py -- cargo test --locked -p rss-mdm-inventory
MDM_TARGET_POOL_N=2 make ci CI_BASE=origin/develop
MDM_TARGET_POOL_N=off CARGO_TARGET_DIR="$PWD/target" make test
```

`make ci-plan` 仅预览，不占槽或启动缓存。直接 `cargo` 使用当前 worktree 的本地产物，不接入上述锁或自动缓存；
不要同时直接操作受管运行正在使用的 target，也不要在启动器的子命令中通过 `--target-dir` 等参数更换 target。

启动器在租用前启动和核验 sccache（要求版本以启动器常量为准），继续共享主 checkout 下的
`.cache/sccache/objects`。可用 `SCCACHE_DIR`、`SCCACHE_SERVER_UDS` 和 `SCCACHE_CACHE_SIZE` 调整；
自定义 rustc wrapper 与该入口冲突。server 版本或路径不匹配时，先确认其使用者全部退出再重启，入口不自动停止共享 server。
缓存可用与命中率不构成测试通过证据。

取消会转发到运行进程组，五秒后仍存活的进程会被终止。若入口被强制杀死，后代进程可能仍持有租约；
不能只凭入口 PID 消失就删除产物或锁文件。锁独立存放在 `~/.cache/rss-mdm-build-locks`，不随 target 清理。
池损坏或遗留进程无法确认时改用新的专用池，并先排查原进程；不删除活跃锁、不自动接管未标记非空目录。
旧公共 target 不自动迁移或清理，确认所有旧构建退出后再自行处理。

## Inventory 调试

示例程序使用受控操作员提供的 `DATABASE_URL`、`PG_CA_FILE`、`MDM_SCOPE_FILE`；scope 文件不是来自请求的认证声明。输入格式见 [fixtures](../../fixtures)，示例入口见 [examples](../../crates/examples)。

```sh
cargo run --locked -p rss-mdm-examples -- ingest-fixture fixtures/snapshot.json
cargo run --locked -p rss-mdm-examples -- project
cargo run --locked -p rss-mdm-examples -- inspect snapshot-1
```

持久 receipt 仅证明报告接收，资产查询须另看投影状态。完整 Snapshot 只替换其明确的 scope/coverage，Partial/Failed 不清空最后完整事实；Delta 需要连续来源序列。提交未知时保留原报告和操作身份查询、精确重放，暂时查不到不能证明回滚。

产品运行和初始化使用 [安装指南](../deployment/installation.md)，不以示例 CLI 代替生产入口。
