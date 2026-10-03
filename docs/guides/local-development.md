# 本地开发

本仓独立维护 Cargo workspace。工具链、依赖和命令分别以 `rust-toolchain.toml`、`Cargo.toml` / `Cargo.lock`、[Makefile](../../Makefile) 为准。先阅读 [协作入口](../../AGENTS.md) 与 [验证规则](../rules/verification-scope.md)。

```sh
make build
make check
make test
make t2
make ci-plan CI_BASE=origin/develop
```

`make ci` 只执行快速检查并报告建议 T2。`make t2` 默认按影响范围选择，显式 `MODULE=planning.http` 运行专项，`MODULE=all` 运行全部；非法模块名及旧 SUITE 参数立即失败。选中的模块按需启动真实依赖，缺少 Docker 或必要工具必须失败。入口直接检查当前工作区，无需预先提交源码。

构建需要 libxml2 开发头文件、pkg-config 和 libclang；Linux 使用 `libxml2-dev clang pkg-config`，macOS 使用 `brew install libxml2 pkg-config llvm`。WinDC 的独立 XMLDSIG 集成测试还需要 `xmlsec1` 命令（macOS：`brew install libxmlsec1`；Linux：`apt-get install xmlsec1`）。WSTEP 证书签名验证使用 libxml2 的原始 DOM 规范化，运行镜像需提供 libxml2；[Dockerfile](../../deployment/Dockerfile) 持有镜像依赖。

## 构建槽位与缓存

Make 的 build/check/test、CI 和定向 T2 入口由 [启动器](../../hack/build_run.py) 管理：默认四个槽，
每次完整命令独占 worktree 和 target，子进程继承租约。worktree 身份由系统 Git 解析，
从子目录启动仍锁定同一 checkout；子命令保留原启动目录。同 worktree 优先复用空闲槽；槽换属时清理旧产物。
槽满、分配器忙、worktree 或目标目录已占用时立即失败，待原运行退出后重试。槽数不限制每个 Cargo 的编译线程数。
换属或退役清理持有该槽独占租约，可为当前用户拥有的 Go 只读缓存目录补用户写权限；不跟随符号链接，不清理活跃槽。权限或 I/O 错误仍终止构建，解决原因后可重试；清理失败不会登记新 owner。

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

## 原生协议 schema 来源与生成

`rss-mdm-native-schema` 是开发工具，不参与产品服务装配。固定来源由
`crates/native-schema/sources/` 中的确定性 ZIP 与 `lock.json` 持有。生成入口先校验归档摘要，
再还原被 Git 忽略的展开目录，并核对归档内逐文件来源、许可证和摘要。Learn 完整正文不入库；
普通离线生成消费 `windows-mdm/schema/learn-facts.json` 的结构化适用性与来源 URL/摘要。
普通构建和生成检查均不下载来源，不跟随浮动分支。

```sh
python3 hack/build_run.py -- cargo run --locked -p rss-mdm-native-schema -- --write
python3 hack/build_run.py -- cargo run --locked -p rss-mdm-native-schema -- --check
python3 hack/build_run.py -- cargo run --locked -p rss-mdm-native-schema -- --check-windows-sources
```

前两条命令生成或核对两平台实际编译使用的 schema，包括 Windows DDF 节点及 ADMX 参数合同。
Apple 历史正式来源合成为一份带版本条件的字段图，
保留原生字段的引入、移除及设备/用户条件，不为旧 RSS wire 生成兼容执行路径。
最后一条命令校验 DDF/ADMX 字节及模板策略引用；来源引用完整不代表 Windows 原生执行已验证。
schema 检查也不替代操作语义、真实 HTTP/DB 接缝或独立真机验证。

来源更新须固定官方 revision 或归档摘要，再重新生成并验证受影响行为。结构化 Learn 事实保留
实际消费的适用性及可追溯 URL/摘要；ADMX 归档保存模板及可取得的许可文本。只有需要重新导入官方 MSI
时才使用 `--import-admx <来源清单> <显式暂存目录>`；该操作只读取已下载且摘要匹配的归档，
不安装或执行其中程序。临时归档和提取目录放在被忽略的 `artifacts/` 下。

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

默认管理 `development` 环境；T2 的普通 PG 使用同一 worktree 的 `t2` 环境，实例故障使用独立的 `t2-fault` 环境，两者可并行，退出时销毁。新一轮开始前会核验归属并清理确定性环境，即使本地目录已丢失。手动恢复时依次运行 `make dev ACTION=reset DEV_ARGS="--group t2"`、`make dev ACTION=reset DEV_ARGS="--group t2-fault"`；网关专项遗留使用 `--group t2-gateway`。stop 保留数据，reset 核验归属后只删除指定环境，不清理共享 target 池。不要直接依赖 Docker Compose 自动推导的项目名。环境数据可丢弃，角色输入不兼容时 reset 后重新 init，没有旧环境升级或兼容解析。

init 使用正式角色 SQL、产品 migrate、initialize 和 initialize-authorization。输出本机 Rust 的配置路径、HTTPS origin 和 nginx 配置路径，账号密码仅写入权限 0600 的 operator/account-password 文件。通过已有构建启动器运行 `rss-mdm serve --config <输出路径>`；`serve` 在绑定管理 listener 后向 stdout 写一行 `{"event":"listener-bound","address":"127.0.0.1:实际端口"}`；`listen` 端口为 0 时由操作系统分配，回执不代表 readiness，仍须探测 `/readyz`。本机 HTTPS 调试使用输出的 nginx 配置，设置 `MDM_WEB_ROOT` 指向已构建 UI，必要时设置 `MDM_NGINX_MIME_TYPES`。私有 CA 仅为该环境使用，不跳过 TLS 校验。

完整容器联调使用已经构建的产品和 UI 镜像，init 固定其实际镜像 ID：

```sh
make dev ACTION=init MODE=container DEV_ARGS="--server-image <产品镜像> --web-image <UI镜像>"
make dev ACTION=up MODE=container
```

产品构建仍使用 release.py 正式入口，`CARGO_BUILD_JOBS` 控制镜像编译并发，BuildKit 缓存按 worktree 命名。网关与应用共享容器网络命名空间，管理端口保持 loopback-only，PG 经 bridge DNS 访问；外部端口只绑定 127.0.0.1。容器重建导致端口变化时重新 init。运行容器不挂载操作员秘密。

每个阶段报告耗时与环境标识。`reuse` 用例在兼容 profile 内共享可写库，并以对象、主体或专用观察租户隔离；每次调用有独立命名空间。`fresh` 为 DDL、库内权限及损坏材料分配一次性库，安装使用空库。`instance` 在故障 PG 内串行，恢复核查成功后复用，失败或不确定则隔离并为后续用例替换环境。原失败不重试；实例角色或停库故障不作用于普通 PG。生命周期与复用资格见[测试模块](test-modules.md)。Windows、Apple 和 IdP 按专项准备。NanoMDM 以校验源码、实际 Go 工具链、平台和参数识别缓存，损坏时只恢复该项。

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

## Windows 原生操作与效果证据

原生输入使用 Windows 的类型化 Node/Atomic/Sequence 或通用 MSI 合同；旧 Firewall、AgentInstall、StateVerify 输入和旧原生派发格式不再解码或转换。产品软件准入仍只允许已有固定 Agent，原生 MSI 编码不持有品牌限制。

操作查询分别展示执行进度、原生回执、`effect` 和 `effectReason`。效果可为 verified、diverged、waiting 或 unverifiable；查询本身不证明变更效果。永久节点 Delete 若恢复默认值但缺少固定检测条件，明确保持 unverifiable 和对象 guards。设备控制、敏感操作及受限诊断没有通用效果查询时记录族专属证据需求；没有实际脚本原生映射时拒绝，不自动转 Agent/安装包。诊断制品、用户身份维护与持续配置由对应生命周期 owner 持有。

ADMX 更新先运行 `python3 hack/native_sources.py prepare` 还原现有机器来源，再导入到新的 `artifacts/` 暂存目录；核对暂存清单、字节和许可证后替换展开的 ADMX 来源目录，运行 `python3 hack/native_sources.py pack` 更新确定性 ZIP/lock，最后运行生成器 `--write`。生成和检查会用固定 ZIP 重建缓存，不能把未经打包的缓存改动当成新来源。来源更新提交包含 ZIP、lock 和实际生成结果。
