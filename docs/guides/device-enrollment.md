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

列表使用 `filter/sort/fields/limit/cursor`，`limit` 默认 64、范围 1–1000；例如 `filter=status==active&sort=-id`。响应为 `items/nextCursor`，不附带统计。`GET /api/v1/devices/statistics` 接受相同 `filter`，独立计算当前权限允许的精确统计并返回 `asOf`。分页每次重新检查权限并读取当前数据；注册或资产变化不作废普通续页，授权或查询上下文改变时重新读取首屏。完整语法见[目录查询](groups-scopes-policies.md)。
详情分别返回产品支持、设备前提和当前操作许可；未知能力不会作为执行许可。

## 原子性与报告来源

签发意图先持久化，证书、注册、回执与成功审计最终同事务提交；已签名但未绑定的证书不具管理权。拒绝/查询审计失败也不放行。日志只记录操作坐标与闭合错误类别，不记录口令、私钥或协议秘密。

设备主体从真实认证与当前持久映射构造，客户端不能声明 tenant、注册世代或报告 scope。报告绑定注册/来源/epoch；同一报告重试保留身份。撤销后的新报告拒绝，撤销前已封存报告仍可按原 scope 恢复投递；不能把这一恢复通道用于任意新报告。

原生接入分别见 [Windows](windows-management.md)、[Apple](apple-management.md)，Agent 接入见 [Agent](agent-integration.md)。迁移与角色配置统一见 [安装](../deployment/installation.md) 和 [运维](../deployment/operations.md)。

Agent 使用独立的持久授权与 mTLS 生命周期，见 [Agent 集成指南](agent-integration.md)。Agent 的自助授权无需原生 Enrollment 权限，不创建五分钟密码授权。

## 自助注册与个人额度

当前组织的有效用户可以直接创建自助注册，无需管理员批准。浏览器入口为“注册我的设备”；原生 MDM 使用 `POST /api/v1/self-enrollments`，参数与组织创建相同但不提供 deviceId。服务端分配独立设备身份，设备上报标识不能选择或覆盖已有组织设备。Windows 保留首次签发时的终端协议标识供后续 SyncML、续证和关联通道校验；该标识不用于跨通道合并。Agent 授权使用 `POST /api/v1/self-enrollments/agent`，沿用 Agent 的持久授权和秘密交付契约。

“注册额度”页面由具有 registration_configuration_read／registration_configuration_write 的管理员读取／配置。每个租户持有自己的默认值和按用户、渠道的覆盖；覆盖留空表示继承，全部清空恢复默认值。0 禁止新增。Agent 的 Windows/macOS 共用一个额度，Windows MDM 和 macOS MDM 各自独立，默认值由注册服务持有。`GET /api/v1/registration-quotas/me` 读取自己的有效额度和当前占用。

占用包括有效设备注册和已授权、未过期的待完成注册；授权重试、续证与凭据恢复不产生第二份占用。取消、过期或撤销后释放相应占用。降低额度保留已有设备与有效待完成注册，超过新额度时禁止新增。额度不足返回 registration_limit；不要将其当作短暂限流自动重试。

## 自助注册引导与当前进度

`GET /api/v1/self-enrollments` 返回当前身份的租户、个人额度和实际配置的原生渠道。渠道的 `requiresLocalAdministrator` 表示本机权限前提，不代表服务端业务授权；没有配置的渠道不会出现在选项中。邀请入口与前端引导页面由后续任务实施。

唯一详情入口 `GET /api/v1/enrollments/{id}` 同时返回生命周期、`instructions` 和 `progress`。Windows 引导包含注册服务器、Discovery 地址、唯一规范用户名和固定的 Full／Device 选择；macOS 引导提供现有 `/api/v1/enrollments/{id}/profile` 地址，以创建时的口令 POST 下载签名 `.mobileconfig`。macOS 用户需在系统设置中确认安装，采用 profile-based device enrollment；用户身份授权不等于 Apple User Enrollment。没有管理员业务权限的员工只能查询／续接／取消自己在当前租户创建的注册。

`profilePrepared` 的 observed 表示服务器准备过当前交接的 profile；未绑定时按当前密码版本隔离，绑定后跟随当前注册及活动凭据对应的 profile／证书，合法续证或 resume 不会把已可管理设备回退为未注册。Windows 返回 not_applicable。`certificateIssued` 是服务器观察到的签发事实，丢失的 SCEP notify 在首次 Authenticate 补齐前仍为 false。下载 profile 或证书签发均不代表完成。`firstAuthenticatedCheckIn` 表示 Windows 双向 SyncML 认证完成，或 Apple Authenticate 已绑定设备；Apple 还必须收到 TokenUpdate。系统弹窗没有服务端观察来源，`systemConfirmation` 始终为 unknown。

`managementReady` 同时检查当前活动注册、当前可用凭据／PKI 信任、首次认证和通道准入。撤销、替代、证书或 CRL 失效后可回退为 false。Windows 首次认证事实保存在注册记录中，临时会话清理不会抹掉它；旧数据迁移后该事实为空，需下一次真实认证才能建立。

`diagnostic` 提供闭合状态：awaiting_system_confirmation、awaiting_certificate、awaiting_first_check_in、awaiting_device_token、reauthentication_required、expired、cancelled、revoked、superseded、credential_unavailable、channel_unavailable、ready。进程重启丢失未绑定授权的会话续接引用时，需要原用户重新登录并 resume；不要自动重发或复活授权。详情响应不包含口令、challenge、token、证书或私钥。

详情契约已直接替换为带引导／进度的响应，Windows 旧用户名不再兼容。现有前端严格解码器需在后续前端任务同步；本次后端实现及协议 T2 不声明真实 Windows／macOS 系统安装已验收。

## 资产所有人与当前使用者

资产所有人复用 `GET/PUT /api/v1/devices/{device}/registration-user`，适用于自助、组织及原生注册设备，也可在已签发的注册待完成时设置。目标设备的 enrollment 权限控制读取和修改；修改使用稳定操作键和 expectedRevision，冲突后重新读取并提交新操作。人员引用使用后端同一 User 坐标；用户选择沿用 Identity 账号查询及其原有权限。

自助注册初始化所有人为本人；管理员代注册、配置签发不把管理员设置为所有人，其余来源允许为空。为空时，后续首次登录 Agent 的企业用户填入；非空时不覆盖。管理员可以修改或清空，清空后新的 Agent 登录仍可填入；精确重放旧登录不重新赋值。历史注册授权人、来源与配额保持原事实，修改所有人也不授予设备管理权。

当前使用者是 Agent 登录的后端用户，沿用同一 Identity 身份。切换或退出 Agent 账号只改变当前使用者。操作系统登录用户保留为独立采集信息，不用来初始化所有人或判定当前使用者。Agent 登录、退出的后端合同见 [Agent 集成](agent-integration.md#agent-企业登录与当前使用者)。

目录与清单的读取一致性、分页及错误语义见[实时目录与固定清单](device-operations.md#实时目录与固定清单)。


## Windows 原证书申请读回

具备设备 Credentials 权限的管理员通过 `GET /api/v1/devices/{device}/windows-certificate-requests` 定位现有登记或续期的原申请，可按 `enrollmentId` 或 `registration` 使用统一查询筛选；`/{attempt}` 读取原申请详情。原 signing issuer、attempt、期限与设备登记代次分别来自原 owner。已经被替代的 attempt 仍沿持久 successor 关系可定位，不会被当前申请冒充。

对象下 `/recovery-operations` 提供原管理恢复操作引用；`/{operation}?actor=...&instance=...` 精确读回原提交结果，两个原主体参数必填。当前有设备凭据权限的管理员可查询他人回执。原 `POST /api/v1/pki/signing/recover` 仍要求全设备 Credentials，并核验原 CSR、公钥、登记身份、原签发者与有效期。

`signing`、`linked` 和 `activated` 是独立事实：原 CA 链关联成功不证明设备领取或已完成持证通信。没有回执不能推断失败或回滚；所需原证书由现有受控运维流程取得。GET 无业务写入，也不调用 CA 或原生恢复流程。
