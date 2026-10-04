# 设备注册与凭据

注册授权与设备身份是两个阶段。创建 pending Enrollment 不代表设备已绑定；bound 表示原子绑定事实，当前凭据是否有效仍由注册状态和管理准入决定。身份与通道世代边界见 [ADR](../architecture/adr/202609100445-2348-device-principal.md)。

## 创建、续接与撤销

先取得 [产品授权](identity-and-authorization.md)。组织创建、resume、cancel 要求 enrollment，撤销要求独立 credentials，并配对目标设备范围。浏览器写操作使用当前会话、Origin、CSRF 和稳定 `Idempotency-Key`。

```sh
python3 hack/enrollment-password.py
```

把生成的随机口令安全交给设备。管理员 cookie/token 不能传给设备。创建请求为 `POST /api/v1/enrollments`，例如：

```json
{"deviceId":"device-1","password":"调用端生成并保存的口令","source":"mdm.windows","windowsProfile":"Full"}
```

原生 Enrollment 的 source 显式选择 mdm.windows 或 mdm.apple，不能由服务猜测。mdm.windows 必须显式提供 `windowsProfile: "Full" | "Device"`，其它来源不得提供此字段。此选择进入幂等输入并在授权后保持不变；设备 EnrollmentType 必须与授权一致。Full 注册的用户上下文标识为该注册的 UUID，可在有权查询的注册列表中读取 `userContextId`；Device 注册不提供用户上下文。查询 `/api/v1/enrollments/{id}` 获取当前状态；注册列表使用 `/api/v1/devices/{device}/registrations`，依 nextCursor 续页，再按 registrationId 撤销。

原管理员重新登录后可向 `/enrollments/{id}/resume` 提交新口令与新操作键；同一请求重试保持原键和参数。恢复保留原注册意图与预期世代，不复活撤销、取消或过期证书。未绑定授权可 cancel；已绑定设备走独立 revoke，撤销同时停用注册、凭据及来源。

响应丢失先查询和精确重放，不换键掩盖未知提交。回执是历史结果，不能代替当前授权；绑定仍需原授权用户在线身份，组织来源还需设备范围授权，进程内续接缓存也不是会话权威。

## 管理设备目录

`GET /api/v1/devices` 返回管理身份目录，包含首次注册 pending、无资产和已撤销设备；
`GET /api/v1/devices/{device}` 返回同一身份及注册、资产存在性和能力摘要。
查询不会提前创建 pending 设备，也不改变 Group/Scope 的执行目标全集。
列表与详情使用现有 `inventory_read` 策略；注册凭据管理继续使用原接口及权限。

列表支持 `limit`（默认 64、1–1000）、`after`、`descending`、`status`、`channel`、`source`。
响应包含 `items`、`nextCursor`、`statistics`、`asOf`；统计只计算当前策略允许且满足筛选的设备，
与列表候选使用同一次数据库读取。分页是当前状态读取，每次请求重新检查权限。
详情分别返回产品支持、设备前提和当前操作许可；未知能力不会作为执行许可。

## 原子性与报告来源

签发意图先持久化，证书、注册、回执与成功审计最终同事务提交；已签名但未绑定的证书不具管理权。拒绝/查询审计失败也不放行。日志只记录操作坐标与闭合错误类别，不记录口令、私钥或协议秘密。

设备主体从真实认证与当前持久映射构造，客户端不能声明 tenant、注册世代或报告 scope。报告绑定注册/来源/epoch；同一报告重试保留身份。撤销后的新报告拒绝，撤销前已封存报告仍可按原 scope 恢复投递；不能把这一恢复通道用于任意新报告。

原生接入分别见 [Windows](windows-management.md)、[Apple](apple-management.md)，Agent 接入见 [Agent](agent-integration.md)。迁移与角色配置统一见 [安装](../deployment/installation.md) 和 [运维](../deployment/operations.md)。

Agent 使用独立的持久授权与 mTLS 生命周期，见 [Agent 集成指南](agent-integration.md)。Agent 的自助授权无需原生 Enrollment 权限，不创建五分钟密码授权。

## 自助注册与个人额度

当前组织的有效用户可以直接创建自助注册，无需管理员批准。浏览器入口为“注册我的设备”；原生 MDM 使用 `POST /api/v1/self-enrollments`，参数与组织创建相同但不提供 deviceId。服务端分配独立设备身份，设备上报标识不能选择或覆盖已有组织设备。Windows 保留首次签发时的终端协议标识供后续 SyncML、续证和关联通道校验；该标识不用于跨通道合并。Agent 授权使用 `POST /api/v1/self-enrollments/agent`，沿用 Agent 的持久授权和秘密交付契约。

“注册额度”页面由具有 authorization_read／authorization_write 的管理员读取／配置。每个租户持有自己的默认值和按用户、渠道的覆盖；覆盖留空表示继承，全部清空恢复默认值。0 禁止新增。Agent 的 Windows/macOS 共用一个额度，Windows MDM 和 macOS MDM 各自独立，默认值由注册服务持有。`GET /api/v1/registration-quotas/me` 读取自己的有效额度和当前占用。

占用包括有效设备注册和已授权、未过期的待完成注册；授权重试、续证与凭据恢复不产生第二份占用。取消、过期或撤销后释放相应占用。降低额度保留已有设备与有效待完成注册，超过新额度时禁止新增。额度不足返回 registration_limit；不要将其当作短暂限流自动重试。

## 组织设备责任人

组织注册始终免个人额度。具有目标设备 enrollment 权限的管理员可以在“注册用户／设备责任人”页面为组织设备选择用户、修改或清空；用户列表复用 Identity 账号查询及其既有权限。设置可以在组织注册待完成时进行。原注册授权人是不可修改的身份／审计来源，设备责任人是独立、可空的归属信息。修改责任人不改变设备、凭据、注册来源或个人额度，也不授予用户设备管理权。更新使用稳定操作键和 expectedRevision，发生版本冲突时重新读取后提交新操作。
