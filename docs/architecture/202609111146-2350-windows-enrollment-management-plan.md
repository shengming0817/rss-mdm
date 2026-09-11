# #2350 + #2351 Windows 注册与管理通道实施计划

状态：已批准并实施；审查与运行证据由交付 PR 绑定。一个 worktree、分支和 PR，同时关联 #2350、#2351。
支持目标：Windows 10 1809 及以上、Windows 11；T1/T2 不替代独立 Windows T3。

## 决策与边界

统一 Enrollment 流程、AccessStore 事务 owner 和 x509-cert 模型。删除旧
`/enrollment-grants`、`/registration-requests`、撤销入口、DTO、配置和执行分支，
不留 alias、shim、双写或旧配置回退。CollectionRun、资产采集、广泛续期和 CA 轮转不在本次范围。

管理 API：

| 接口 | 行为 |
|---|---|
| POST /api/v1/enrollments | 设备 ID 与调用端生成并保留的 256 位随机口令创建授权 |
| POST /api/v1/enrollments/{id}/resume | 原管理员在线重新授权，轮换口令与不可登录会话引用 |
| POST /api/v1/enrollments/{id}/cancel | 取消未完成注册 |
| POST /api/v1/devices/{device}/registrations/{registration}/revoke | 原子撤销注册、凭据及来源授权 |

全部管理写复用在线 Identity、当前资源权限、CSRF 和各自独立幂等键。
只持久化域分离口令摘要，响应不回显口令；提供配套随机口令脚本。
创建时持设备通道锁冻结当前世代，单独生成稳定签发/绑定操作 ID。
grant 保留不可变授权来源，request 是唯一 Enrollment 状态 owner，不新增 ticket 状态机。
默认授权期限 300 秒；恢复保留 Enrollment、CSR、签发操作与预期世代。
管理员 token/cookie 只在进程会话内；PG 中会话引用不能登录。重启后原管理员重新认证恢复。
已绑定结果仅在原凭据仍有效时读取，不能重签或复活撤销凭据。

产品 app 终止注册 HTTPS 和独立管理 mTLS，不接受代理身份头。
codec 仅负责有界 Discovery/XCEP/WSTEP、provisioning XML、Fault 与 SyncML 编解码，
补齐必要可选字段，修正 XCEP SHA-256 OID 为 hash group。
CSR 严格 DER、拒绝尾随数据、重编码一致且验证公钥持有证明；
固定 RSA/SHA-256，最低 2048 位，上限复用 ring 有界验证；subject/扩展/DeviceID 不授予权限。
RSA/SHA-256 签名参数接受标准 NULL 或省略，输出规范 NULL。

受保护 RSA PKCS#8 产品 CA 启动校验密钥匹配、用途、有效期。
叶证书 clientAuth、digitalSignature、CA=false，默认 90 天且不超 issuer。
仅保留两个持久事实：不可变签发意图（精确 TBS DER、issuer、序列号、时间、公钥、
配置身份），以及证书/注册绑定/完成回执/成功审计的原子最终提交。
RSA PKCS#1 v1.5 SHA-256 确定性签名；提交未知按原操作读回，无结果才从原意图重算。
不能确认则返回未知，不更换操作或 issuer；最终事务重查期限、口令版本、取消和世代。
提交成功前不发布证书，已签未绑定证书不能通过管理准入。

每个管理请求重验链、期限、显式 clientAuth/用途，通过叶证书 SHA-256 查询 I01 当前映射，
只有该路径可构造可信 DevicePrincipal。固定 APPSRV BASIC、CLIENT DIGEST；
每注册独立秘密由独立于 CA/TLS 的密钥加密持久化。
会话绑定租户、注册、世代、证书；Cred、Challenge、nonce、SyncHdr 关联与
准确响应同事务保存，重传不推进状态，错误 session/reference/DeviceID/跨设备请求拒绝。
撤销提交后的新准入立即拒绝，已准入请求最多 8 秒并预留 2 秒审计。

## 实施 DAG 与 owner

主 agent 独占所有代码、Cargo、迁移和测试修改；探索与内置 review agent 只读。

1. 本计划、失败用例：codec SHA-256 OID、口令验证/恢复、CSR、TLS/协议与真实 PG。
2. Enrollment/迁移：app enrollment/access_store/api/sessions/device；一个追加迁移单元。
   保留历史身份、操作和审计，终止旧未绑定请求及未消费许可，不转换可用 Windows 凭据。
   所有 RLS 与最低角色授权随新 schema 一起检查，不支持旧二进制混跑。
3. CSR/签发与注册：app 产品 CA、HTTPS handlers 与 codec provisioning。
4. mTLS/协议会话：app TLS listener、I01 准入、加密秘密、事务会话重放。
5. 集成验证/文档：自动生成 CA、证书、CSR、协议样本、配置与故障环境，临时私钥不入库。
6. 单 PR、内置 review、findings 修复与交接。

编辑循环：受影响 app/codec 测试和 `make t2`；提交受测源码后执行产品 `make ci`。
T2 使用真实 PG、真实签名和 TLS，覆盖丢响应、签后保存失败、提交未知、重启、
并发换代、撤销竞争、审计失败、错误证书/租户/世代及重放。
追加升级验证证明旧待办不能恢复且历史事实保留。
PR 记录固定 HEAD、依赖、实际结果及未覆盖项，不用 T1/T2 宣称 Windows T3 已通过。

## 上游参考

- [RFC 4055 §5](https://www.rfc-editor.org/rfc/rfc4055.html#section-5)
- [RustCrypto x509-cert 0.2.5 request.rs](https://github.com/RustCrypto/formats/blob/x509-cert/v0.2.5/x509-cert/src/request.rs)
- [Microsoft w7 APPLICATION CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/w7-application-csp)
