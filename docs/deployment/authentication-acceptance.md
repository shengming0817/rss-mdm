# 产品认证浏览器验收

本入口独立运行正式 MDM binary、rss-web 认证镜像、自有 TLS PostgreSQL、同源网关与私网 Keycloak。
不运行 Identity 参考应用或其数据库，不以 T1/T2 或脚本检查代替浏览器结果。

## 执行

按 [安装指南](installation.md) 构建 V3 候选。使用与验收工具匹配的固定浏览器镜像，版本由 auth_t3.py 校验；运行不依赖源码 checkout。使用当前 Docker 默认平台。镜像须已存在，UI 由产品候选归档持有；工具输入仅接受不可变 image ID 或 repository digest，启动前导出 browser-tools.image.tar 并记录摘要，不接受 tag。

```sh
python3 hack/auth_t3.py --candidate /absolute/candidate --tools-image "$MDM_BROWSER_IMAGE_ID" --output /absolute/new-result
```

输出目录必须全新。失败不生成 result.json；成功记录只在全部场景及资源清理完成后写入。
requests.json 保存 origin、路径、状态及产品请求 ID，audit.json 保存产品审计关联，product.log 按容器保存安全产品/网关日志；不保存请求正文、密码、cookie、code 或 client secret。
result.json 记录候选、UI、工具/浏览器版本、域名、CA、配置和日志摘要。
故障注入限于随机命名的本任务容器与网络，结束逐一清理，不执行全局 prune。

## 证明边界

浏览器覆盖登录/账户页面、同源 cookie/CSRF、实际资源授权、刷新/退出/全部撤销、账户停用/成员移除、重启、实例/租户隔离、生产私网 OIDC 显式关联及未知主体拒绝、IdP/PG 故障与恢复。
资产为明确标记的合成 `device-1` / `Model-2364` 读模型，真实产品查询、权限和审计仍执行；不宣称真实设备注册或采集成功。
management 覆盖真实组创建/读取与拒绝无效果；publisher 覆盖显式 release_read 许可到资源查找及拒绝，不宣称实际软件发布。
历史策略为全新实例，不自动映射旧主体；旧审计保持原含义，不转换、不删除。安装坐标错配验证拒绝且账户和账本不变；不证明真实旧环境已经退役。

此处描述可执行验收，实际通过与否以本次运行记录和 PR 证据为准。

PG 故障可能先产生产品 503，再触发关键任务失败关闭，网关随后返回 502。两者均须拒绝授权；UI 保留失败/结果未确认提示。恢复 PG 后由部署 owner 重启 MDM，再检查持久会话并明确退出。

工具归档保留在本次输出目录，跨主机恢复时核验 result.json 中 tools.archive.sha256 后 docker load，运行相同 tools.id；工具不是生产容器。秘密在宿主以私有目录/文件持有，经命名卷交给明确 UID，容器内检查 0600 和 owner；一次性容器也在启动前登记，超时仍回收 daemon 资源。
