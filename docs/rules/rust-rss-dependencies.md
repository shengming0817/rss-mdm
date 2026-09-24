# Rust 与跨仓依赖

自有服务端与 Agent 使用 Rust，分别维护 workspace、lock 和工具链。只消费已接纳公共 API，不引用仓外 path、父仓内部源码或复制通用持久机制。

RSS 直接依赖固定同一完整 Git rev，Identity 公共组件固定其独立仓同一 rev；精确值由 Cargo.toml/Cargo.lock 持有，来源不可取得时失败，不浮动跟踪分支或保留备用来源。产品成员使用 workspace 内部 path，身份和位置由 metadata 核查。凭据由系统 Git helper/受保护构建 secret 提供，不写入 manifest 或日志。

正常工作区 locked 构建与 normal/all-features metadata 校验依赖来源和安全约束，不以隔离 consumer、tree 导出或冷构建形成额外证明体系。源码 Git 消费不称为 registry 发布。升级依赖时验证受影响 API/features/schema、错误与提交未知语义、关闭和真实产品接缝；缺口回原 owner 修复。

## 产品边界

纯决策核心不依赖 HTTP/PG/设备通道，各核心不泄漏其它业务类型；平台源只带自身必要接缝。PG adapter 依赖对应核心及 RSS/PG，组合根持有跨 owner 映射与事务。边界理由见 [基础 ADR](../architecture/adr/202609072231-001-rust-rss-product-foundation.md)。

Policy、Resource、Software Release 的 PG adapter 可依赖同 workspace 的 backend-postgres-support。支持包不依赖 MDM 核心/adapter/app/identity，不扩张为通用平台或迫使其它能力接入。实际禁止依赖与安全 allow-list 由 [CI](../../hack/ci.py) 持有。

Agent 只带目标平台所需公共核心/值类型，不带服务端 PG/broker/运行角色。共享 wire 归协议包唯一维护，两端的能力、schema 和升级窗口须按真实集成验证，不以模拟消费者代替。

## Identity 与安全

MDM 直接装配公开认证组件并持有产品权限，不依赖 Identity 参考应用。OIDC RSA 仅作公钥验证；既有风险接受的精确路径与约束由 [deny.toml](../../deny.toml) 和 CI 持有，升级后重新检查最终 lock，不继承旧路径豁免。生产装配不启用测试 loopback 能力。
