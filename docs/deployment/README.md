# 部署与运维

本目录承载私有化安装、配置、证书及 Apple 外部依赖、数据库迁移、升级回退、备份恢复与运行诊断。已有 Linux arm64 候选构建入口；发布资格以具体候选的受测证据和独立 T3 为准。

文档按实际支持矩阵记录版本、权限、资源和网络前提、执行步骤、成功判据及失败恢复。历史 Compose 文件仅作参考，不能直接作为本仓受支持部署方式。生产交付遵循 [验证规则](../rules/verification-scope.md)。

Windows 协议监听、CA/保护密钥、升级顺序和恢复边界见 [Windows 注册与管理通道](../guides/202609111146-2350-windows-enrollment-management.md) 与 [Enrollment 操作](../guides/202609090001-2347-enrollment-audit.md)。

- [Linux arm64 候选部署](202609120000-2353-linux-arm64.md)（#2353）：OCI、配置、迁移、健康与关闭。
