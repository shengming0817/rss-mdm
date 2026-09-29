# 本地开发

本仓独立维护 Cargo workspace。工具链、依赖和命令分别以 `rust-toolchain.toml`、`Cargo.toml` / `Cargo.lock`、[Makefile](../../Makefile) 为准。先阅读 [协作入口](../../AGENTS.md) 与 [验证规则](../rules/verification-scope.md)。

```sh
make build
make check
make test
make t2
make ci-plan CI_BASE=origin/develop
```

`make ci` 只执行快速检查并报告建议 T2。`make t2` 默认按影响范围选择，显式 `MODULE=planning.http` 运行专项，`MODULE=all` 运行全部；非法模块名及旧 SUITE 参数立即失败。选中的模块按需启动真实依赖，缺少 Docker 或必要工具必须失败。编辑循环选择受影响测试，最终检查不要求先提交源码。

## 构建槽位与缓存

Make 的 build/check/test、CI 和定向 T2 入口由 [启动器](../../hack/build_run.py) 管理：默认四个槽，
每次完整命令独占 worktree 和 target，子进程继承租约。worktree 身份由系统 Git 解析，
从子目录启动仍锁定同一 checkout；子命令保留原启动目录。同 worktree 优先复用空闲槽；槽换属时清理旧产物。
槽满、分配器忙、worktree 或目标目录已占用时立即失败，待原运行退出后重试。槽数不限制每个 Cargo 的编译线程数。

| 配置 | 行为 |
| --- | --- |
| `MDM_TARGET_POOL_N` | 默认 `4`；正整数调整槽数，`0/off` 改用当前 worktree 的 target |
| `MDM_TARGET_POOL_ROOT` | 默认 `~/.cache/rss-mdm-cargo-target-pool`，必须是空目录或已标记的专用池 |
| `CARGO_TARGET_DIR` | 显式目录绕过池分配，仍须取得独占锁；不能与显式正数槽配置共用，也不能指向池内部 |

例如定向验证使用同一个启动器，不直接运行正式 CI/T2 脚本；这些脚本在缺失有效租约时会拒绝执行。

```sh
python3 hack/build_run.py -- cargo test --locked -p rss-mdm-inventory
MDM_TARGET_POOL_N=2 make ci CI_BASE=origin/develop
MDM_TARGET_POOL_N=off CARGO_TARGET_DIR="$PWD/target" make test
```

`make ci-plan` 仅预览，不占槽或启动缓存。直接 `cargo` 使用当前 worktree 的本地产物，不接入上述锁或自动缓存；
不要同时直接操作受管运行正在使用的 target，也不要在启动器的子命令中通过 `--target-dir` 等参数更换 target。

受管运行直接调用 rustc，复用槽内 target 的增量产物，不启用 sccache。独立缓存服务可能在客户端退出后
继续写入 target，无法由客户端租约保护；因此删除旧缓存 wrapper，不保留自动缓存配置分支。
入口拒绝显式自定义 rustc wrapper，并覆盖祖先 Cargo 配置中的 wrapper。旧共享缓存和服务不自动清理或停止。

锁键统一折叠路径大小写和 Unicode 规范形式，保证目录被 `cargo clean` 删除、以不同拼写重建后仍互斥。
因此在大小写敏感文件系统上，仅拼写大小写或 Unicode 形式不同的目录也可能被保守地判为占用。

INT/TERM/HUP/QUIT 取消信号会转发到运行进程组，五秒后仍存活的进程会被终止。若入口被强制杀死，后代进程可能仍持有租约；
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

## Worktree 开发环境

默认四槽共享 target 池及其独占租约保持不变。环境归属由 worktree 绝对路径决定，和槽位分配、复用、换属无关；四个 worktree 可并行开发，槽满时构建明确失败。

```sh
make dev ACTION=up
make dev ACTION=init
make dev ACTION=status
make dev ACTION=stop
make dev ACTION=reset
make t2 MODULE=planning.http
make t2 MODULE=affected CI_BASE=origin/develop
make t2 MODULE=all
make t2 MODULE=content.http LIST=1
make t2 MODULE=content.http CASE='<LIST 输出的完整测试 ID>'
```

默认管理 `development` 环境；T2 使用同一 worktree 的 `t2` 环境，一次运行复用一个 PG 服务，退出时销毁。破坏性模块在普通阶段结束后独占并重置同一服务。显式清理遗留 T2 环境使用 `DEV_ARGS="--group t2"`；启动新一轮前也会核验归属并清理旧服务。stop 保留数据，reset 核验归属后只删除指定环境，不清理共享 target 池。不要直接依赖 Docker Compose 自动推导的项目名。环境数据可丢弃，角色输入不兼容时 reset 后重新 init，没有旧环境升级或兼容解析。

init 使用正式角色 SQL、产品 migrate、initialize 和 initialize-authorization。输出本机 Rust 的配置路径、HTTPS origin 和 nginx 配置路径，账号密码仅写入权限 0600 的 operator/account-password 文件。通过已有构建启动器运行 `rss-mdm serve --config <输出路径>`；本机 HTTPS 调试使用输出的 nginx 配置，设置 `MDM_WEB_ROOT` 指向已构建 UI，必要时设置 `MDM_NGINX_MIME_TYPES`。私有 CA 仅为该环境使用，不跳过 TLS 校验。

完整容器联调使用已经构建的产品和 UI 镜像，init 固定其实际镜像 ID：

```sh
make dev ACTION=init MODE=container DEV_ARGS="--server-image <产品镜像> --web-image <UI镜像>"
make dev ACTION=up MODE=container
```

产品构建仍使用 release.py 正式入口，`CARGO_BUILD_JOBS` 控制镜像编译并发，BuildKit 缓存按 worktree 命名。网关与应用共享容器网络命名空间，管理端口保持 loopback-only，PG 经 bridge DNS 访问；外部端口只绑定 127.0.0.1。容器重建导致端口变化时重新 init。运行容器不挂载操作员秘密。

每个阶段报告耗时与环境标识。普通测试重建自己的数据库并保留真实提交，PG 与 CA 复用；角色、权限或停库故障不作用于普通 PG。Windows、Apple 和 IdP 按专项准备。NanoMDM 以校验源码、实际 Go 工具链、平台和参数识别缓存，损坏时只恢复该项。

## 浏览器正常与故障验证

正常模式消费已准备好的测试账号、数据及两个 HTTPS 地址，不要求 Docker 权限：

```sh
MDM_PLAYWRIGHT_MODULE=<本机playwright-core绝对路径> make t3-auth T3_ARGS="--mode normal --input <0600输入JSON> --output <新结果目录>"
```

输入包含 `mode: normal`、`origin`、`otherOrigin`、`tenant`、`otherTenant`、`wrongTenant`、`member`、`ssoMember`、`adminPassword`、`memberPassword`、`issuer`、`idpPassword`、`clientSecret`、`caFile`，不接受容器或服务控制坐标。运行前将该测试环境 CA 配置到本机浏览器信任库，准备专用测试账号与 Inventory 数据；正常用例会通过产品 API 修改这些测试账号及授权数据。

故障模式继续消费固定候选及浏览器工具镜像：

```sh
make t3-auth T3_ARGS="--mode faults --candidate <候选目录> --tools-image <固定工具镜像> --output <新结果目录>"
```

重启、停 IdP、暂停 PG、安装失配及数据库白盒断言只在其新建专用环境运行。normal 和 faults 分别报告覆盖，normal 成功不表示完整候选或故障验证通过。

更新受审查的 catalog 快照使用 `python3 hack/build_run.py -- python3 hack/command_catalog.py --write`，检查仍只用 `make t2 MODULE=catalog.contract`。宿主端口由带锁的跨 worktree 分配记录协调，init 检查占用；出现外部进程占用时停止该进程，或 reset 后重新 init 获取空闲端口。

多个 localhost 端口的浏览器调试使用独立浏览器 profile 或自动化 context；Cookie 按主机而非端口隔离。

T2 的模块职责、选择边界、并发与结果格式见[测试模块](test-modules.md)。`JOBS=1` 可顺序诊断；默认 `JOBS=2`。LIST 只构建和发现测试，不启动服务，不覆盖正式执行结果。
