# RSS 与历史产品基线复核

复核日期：2026-09-07。此页仅记录本轮目标设计所需证据，不作为持续发布台账或产品测试通过记录。

## 固定来源

| 来源 | 固定身份 | 使用边界 |
| --- | --- | --- |
| RSS | `1b650c16628ca84834b1b2b4784170dd85e2319e` | 以下 R 路径相对该 commit；父目录未提交的 verification-scope 修改及本地分析文档未作为固定基线 |
| rss-mdm | `e64d76048d5e825ab6700e48382770662ecf49df` | 已合并初始文档；没有产品 Rust workspace |
| rss-mdm-agent | `f423420236804a468b7c7fc54fce38f65ea7710c` | 空初始提交，没有可运行 Agent |
| WinMDM 归档 | SHA-256 `bb08749e671080dd96a3d61dd31c662730604cd288303fa67e7917aaf9778e67` | G 路径相对本地历史快照；恢复见 [来源说明](../../reference/README.md) |

RSS 固定版本可从 [Azure DevOps](https://dev.azure.com/shengming0923/rss/_git/rss?version=GC1b650c16628ca84834b1b2b4784170dd85e2319e) 查阅。在 RSS checkout 使用 `/usr/bin/git show 1b650c16628ca84834b1b2b4784170dd85e2319e:<path>` 可复核，不依赖产品访问父目录。

外部方案作为设计输入；以下结论按固定基线独立复核，不沿用外部附件的证据编号。

## 当前代码结论

| ID | 路径与定位 | 结论及限制 |
| --- | --- | --- |
| R01 | `Cargo.toml:5`、`:51`，`rust-toolchain.toml:3` | 42 workspace members（32 crates + 10 integration packages）、31 Release Surface entries；工具链 pin 为 1.96.0。不是旧快照 39/29，数量不代表成熟度 |
| R02 | `crates/axum/Cargo.toml:14`、`crates/axum/src/server.rs:23/40/60`；`crates/axum/tests/protocols.rs:81/331/359` | H1/H2/Auto 已有公共入口与测试；Auto 是明文协议检测，不提供 TLS/ALPN/h2c Upgrade，旧 H2-only 结论失效 |
| R03 | `crates/observation-postgres/Cargo.toml:17`、`crates/observation-postgres/src/projection.rs:15/77/109` | PgSource 消费 journal，并能在 Projection 借用事务中解析原记录；不依赖 Device Command 或消息运行时 |
| R04 | `crates/observation-postgres/examples/handoff/model.rs:22`、`tests/postgres-integration/tests/observation_projection/mod.rs:7` | 已有 facts/checkpoint 原子组合和真实 PG 测试源码，包括顺序、隔离、进程恢复；不是产品 Inventory/认证实现 |
| R05 | `hack/observation-package-proof.py:14/18/97`、`.github/workflows/candidate-bundle.yml:49/149/167` | 八个 RSS artifact 的四种独立组合，校验版本/revision/hash；handoff 只编译，不能充当真实 PG 产品运行证明；workflow 存在不证明该 HEAD 产物已生成 |
| R06 | `crates/reconcile-postgres/src/messaging.rs:38/89`；`crates/device-command-postgres/src/store.rs:73/164` | 可选 messaging 路径能够借用同一消息事务组合；默认 reconcile 事务是另一类型，不能混用 |
| R07 | `crates/transactional-messaging-postgres/src/outbox.rs:28`、`crates/transactional-messaging-postgres/src/transaction.rs:394/646` | PgRuntime 在自己的事务路径中结算；outbox 具有 runtime provenance，必须同一实例 |
| R08 | `crates/device-command/src/model.rs:75`、`crates/device-command/src/state.rs:236`、`crates/device-command-postgres/migrations/0001_create_device_command.sql` | 设备级 authority、租户级 command ID 和 exact expected-state digest；取消/超时/替代不撤销已到终端动作 |
| R09 | `crates/reconcile/src/model.rs:64`、`crates/reconcile/src/worker.rs:260`；`crates/transactional-messaging/src/fence.rs:9` | reconcile claim 与 messaging DR fence 是不同权威坐标；apply 后需要 reobserve，不能冒充设备实际已收敛 |
| R10 | `crates/projection-postgres/src/transaction.rs:9`、`crates/observation-postgres/src/store.rs` | 各 store 有自身 pool/lifecycle；clone pool 不提供关闭隔离，共享数据库不等于共享事务 |
| R11 | `RELEASES.md:6/24`、`Cargo.toml:55` | release entries 为 experimental；发布由维护者执行，CI 不上传。兼容政策/registry发布/当前HEAD产物是不同事实 |
| G01 | `src/internal/application/mdm/enrollment_service.go:189/308`、`src/internal/api/mdm/middleware/mtls.go` | 旧注册有密码验证、CSR和记录持久化；证书链/撤销检查不足以代替设备主体绑定 |
| G02 | `src/internal/application/mdm/management_service.go:288` | 旧管理路径使用 SyncML 自报 deviceID 查设备；新链必须从证书→注册绑定得到 DevicePrincipal，不能复制此信任假设 |
| G03 | `src-agent/engine/poller.go:272`、`src-agent/storage/queue.go:19`、`src/internal/domain/agent/repository.go:73` | 生产 poller 仅校验/日志；队列组件未接成执行回传链，任务 repository 无 Create。Rust Agent 是补闭环，不是成熟执行链逐行翻译 |
| G04 | `README.md:17`、`docker-compose.yml:52` | 前端引用 ../winmdm-web，当前未取得；相邻 rss-web 是 RSS 客户端，不能冒充旧 MDM 控制台 |

上述路径定位源码，不表示已执行相应产品场景。

## Artifact 可取得性

本轮只读查询 crates.io sparse index：Observation/Projection 等首项目标包尚无公开条目；diag-context、trace-context 已有较早 0.1.0，不能据此认定全体 RSS 从未发布，也不能把同号旧产物当本 HEAD。实现 F01 时重新核对所选八包及其完整上游闭包的可取得性；候选 bundle 必须真实生成/取得并验证，当前没有填写产品 lock 或已验证摘要。

查询入口：[Observation index](https://index.crates.io/rs/s-/rss-observation)、[Projection index](https://index.crates.io/rs/s-/rss-projection)、[diag-context index](https://index.crates.io/rs/s-/rss-diag-context)、[trace-context index](https://index.crates.io/rs/s-/rss-trace-context)。不存在公开条目不排除已有私有制品；发布策略由 RSS owner 处理，本目标 PR 不修改其 registry 或兼容 metadata。

## 协议对照

- Windows 注册包含授权、证书安装和后续双向 TLS 管理连接；因此 V1 必须闭合证书到产品注册主体的绑定。[Microsoft enrollment](https://learn.microsoft.com/en-us/windows/client-management/mobile-device-enrollment)
- Status 的 MsgRef 与 CmdRef 指向原消息和命令；只按 device + CmdID 不足以长期关联。[Microsoft SyncML Status](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/36b1a4d9-fd93-48ce-b865-6a9d396c52a4)
- Antivirus/Status 的 0 与 SignatureStatus 的 0 含义不同，不能统一按“0异常”解释；具体字段枚举由产品 adapter 维护。[Microsoft DeviceStatus CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp)
- XML namespace 可使用成熟 parser；parser 不等于完整 MDM codec或输入预算。[quick-xml NsReader](https://docs.rs/quick-xml/latest/quick_xml/reader/struct.NsReader.html)

## 验证边界

本轮完成源码、manifest、测试定义、artifact脚本与官方协议资料核对。探索中实际运行 device-command 状态 9 项、reconcile worker 12 项、reconcile messaging surface 1 项并编译 device-command compose 示例，均通过；这些只是库级验证。未运行 PostgreSQL/Docker T2、broker、Windows/macOS T3、Agent 或前端，也未证明 Reconcile+Command+Outbox 的产品三方组合。对应证明必须在实施切片取得。
