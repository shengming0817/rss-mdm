# 设备注册与凭据

管理员注册授权与设备身份是两个阶段。创建 pending Enrollment 不代表设备已绑定；bound 表示原子绑定事实，当前凭据是否有效仍由注册状态和管理准入决定。身份与通道世代边界见 [ADR](../architecture/adr/202609100445-2348-device-principal.md)。

## 创建、续接与撤销

先取得 [产品授权](identity-and-authorization.md)。创建、resume、cancel 要求 enrollment，撤销要求独立 credentials，并配对目标设备范围。浏览器写操作使用当前会话、Origin、CSRF 和稳定 `Idempotency-Key`。

```sh
python3 hack/enrollment-password.py
```

把生成的随机口令安全交给设备。管理员 cookie/token 不能传给设备。创建请求为 `POST /api/v3/enrollments`，例如：

```json
{"deviceId":"device-1","password":"调用端生成并保存的口令","source":"mdm.windows"}
```

source 显式选择 mdm.windows、mdm.apple 或 agent.builtin，不能由服务猜测。查询 `/api/v3/enrollments/{id}` 获取当前状态；注册列表使用 `/api/v3/devices/{device}/registrations`，依 nextCursor 续页，再按 registrationId 撤销。

原管理员重新登录后可向 `/enrollments/{id}/resume` 提交新口令与新操作键；同一请求重试保持原键和参数。恢复保留原注册意图与预期世代，不复活撤销、取消或过期证书。未绑定授权可 cancel；已绑定设备走独立 revoke，撤销同时停用注册、凭据及来源。

响应丢失先查询和精确重放，不换键掩盖未知提交。回执是历史结果，不能代替当前授权；绑定仍需原管理员在线授权，进程内续接缓存也不是会话权威。

## 原子性与报告来源

签发意图先持久化，证书、注册、回执与成功审计最终同事务提交；已签名但未绑定的证书不具管理权。拒绝/查询审计失败也不放行。日志只记录操作坐标与闭合错误类别，不记录口令、私钥或协议秘密。

设备主体从真实认证与当前持久映射构造，客户端不能声明 tenant、注册世代或报告 scope。报告绑定注册/来源/epoch；同一报告重试保留身份。撤销后的新报告拒绝，撤销前已封存报告仍可按原 scope 恢复投递；不能把这一恢复通道用于任意新报告。

原生接入分别见 [Windows](windows-management.md)、[Apple](apple-management.md)，Agent 接入见 [Agent](agent-integration.md)。迁移与角色配置统一见 [安装](../deployment/installation.md) 和 [运维](../deployment/operations.md)。
