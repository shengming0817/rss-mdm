# HTTP 契约按需生成与消费

完整自有管理 HTTP 与 Agent API 契约按需从源码生成，不再提交后端 Git。格式为 V1，schema 使用 JSON Schema 2020-12。App 的离线导出复用生产的路由注册、路径组合、配置静态路径及条件挂载，不启动服务、不连接数据库、不构造虚假服务状态。

受保护端点的 `authentication` 引用实际管理认证 owner；`alternatives` 为互斥凭据方式，各自包含 header schema、必填 header 和限制。Cookie 的写请求要求 Origin、`X-Identity-Request: 1` 和 session 绑定的 CSRF，GET/HEAD 使用被动认证；Bearer/API key 仅在实际允许的入口出现。`conditional_response_headers` 描述 401 的 `WWW-Authenticate` 条件，不能作为每个 401 都必含该 header 的承诺。描述在最终路径组合后解析，租户管理及自助入口保留实际凭据限制。认证 owner 在 handler 之前可能产生的拒绝响应也合并到端点唯一的 `responses` 集合；客户端按同一契约验证状态、错误体和响应头，认证失效继续交由既有会话 owner 处理。

## 按需导出

在需要消费的后端源码 checkout 根目录执行：

```sh
python3 hack/http_contract_artifact.py --output artifacts/http-contract/http-v1.json
```

输出路径相对于命令工作目录，父目录会自动创建；重复执行会覆盖该输出。`artifacts/` 已忽略；原 `contracts/http-v1.json` 路径也已忽略，不能强制加入 Git。导出只写指定文件，不更新 Collection 消费视图，不生成来源回执。

命令需要 Python、仓库固定的 Rust 工具链及 Cargo 依赖，使用现有构建 lease 和缓存，不需要启动后端或数据库。生成结果来自当前 checkout 的实际源码，包含未提交改动；工具不把 HEAD 自动声明为输出来源。

`apps/server/examples/http_contract.rs` 是产品组合层入口。`http-contract` 只描述注册到 Axum 的实际参数与响应类型；不执行第二套 extractor、handler 或 middleware。查询 owner 同时提供参数声明和实际解析入口，保留原授权与延迟解析顺序。

## 制品结构

- `endpoints` 按 listener、method、path 排序。`operationId` 为 `listener:METHOD:path`，`handler` 保留实际 Rust handler 来源。
- `request` 包含 path、query、body 和 headers。body 同时声明媒体类型；`required_headers` 记录实际必需 header。响应按实际 HTTP status、媒体类型、body 和 header 描述，错误使用真实 HTTP 投影，不导出内部错误枚举作为回包。
- 每个 schema 描述含 `direction` 与 `schemaId`。`schemas[schemaId]` 是独立的 schema 根；其中 `#/$defs/...` 必须相对于该根解析。请求按 deserialize、响应按 serialize 派生，省略字段与显式 null 不等同。二进制、范围下载、压缩入口、数值编码继续由原传输 owner 执行。
- `conditions` 表示真实条件挂载。完整导出包含这些条件下的端点全集，包括 `device_access_registration` 条件下的 DA 独立 listener；条件名称不是部署能力探测或版本握手。`agent_listener` 要求产品实际启用 Agent listener；各服务条件仍由生产装配决定。
- `configuredPath` 描述配置绑定的静态 UUID 路径段。例如 management tenant 路径保留生产中静态路由优先于普通捕获路由的语义，记录配置来源及被覆盖的 operation，不写入某个部署的 UUID。
- `external` 标记已挂载的 Apple/Windows/软件仓库原生协议入口，`externalOwners` 记录 Identity SDK 边界。平台模块中的自有管理和 Agent 接口仍属于 `endpoints`。原生状态叶子等明确的外部协议数据由其原 owner 校验，不能据此放开核心身份、动作或状态结构。

Schema 中的 `x-rss-extension` 仅标识具体扩展位置及其 owner，例如 Resource 输出、展示元数据、Apple 已验证的原生 status 叶子。它不表示整个响应可接受任意 JSON。动态字段和列表仍由 Inventory/用户 schema 解释。

资产数组和采集作用域分页分别使用 `POST /api/v1/devices/{id}/inventory-lists/{field}`、
`POST /api/v1/devices/{id}/inventory-scopes`。JSON 请求体包含可选 `limit`、`cursor`；数组分页还可传
类型化 `scope`。不使用 URL 参数；浏览器会话按 POST 规则提供 CSRF。两者仍是仅需原读取权限的只读
操作，不追加管理变更审计。token 自包含固定 `AssetCut`，最大 256 KiB；Rust 与 Nginx 的请求体预算均为
384 KiB。固定快照不得放入 URI（HTTP URI 类型自身有长度上限）。已有查询任务的结果分页引用原任务
输入，不复制 snapshot；其它分页接口不变。

## 目录查询能力

目录的 `request.query_owner` 与实际执行使用同一份领域声明。公开业务模型中的标量、嵌套业务属性和标量集合默认进入过滤范围；可信存储绑定及权限仍由原 owner 持有。字段描述给出 `kind`、`operators`、`filter/sort/output`、`nullable` 和 `limitation`，客户端直接消费，不另维护白名单。

例如 Resource 使用 `presentation.name=icontains=工具;presentation.category=in=(Tools,Office)`，证书使用 `latest.metadata.labels=containsall=(managed,mac)`，Webhook 使用 `settings.presentation.name=icontains=receiver`，ADE Profile 使用 `configuration.name=icontains=Mac`。URL 仍须标准编码；`==` 为精确比较，`=icontains=` 在两侧使用 PostgreSQL `pg_c_utf8` 的 `upper(lower(...))` 统一简单大小写后进行字面包含（Σ/σ/ς、I/i/İ/ı 各为同一类；ß/ẞ 同类但不展开为 ss），`%`、`_` 和引号不会变成 SQL 通配或代码。

过滤、排序与返回分别声明。嵌套属性可过滤不代表可以使用 `fields=父对象.属性`；当前目录返回原有顶层容器，可排序标量使用稳定唯一键及 NULLS LAST。普通可空目录元数据的缺失和 JSON null 作为 SQL NULL，使用 `=isnull=true`／`=isnotnull=true`；`!=` 不匹配空值。设备与资产已有 unknown/conflict 语义由原 owner 保持。

目录只对模型可保证游标大小的字段声明排序；无界描述、保存查询文本和未规定长度的名称仍支持过滤与返回。多个排序键的累计游标预算在解析时检查，超限请求在查询前拒绝。

`=containsany=`／`=containsall=` 对标量集合分别表示包含任一／全部候选值。复杂对象数组、递归条件定义、动态参数和无类型扩展键在声明中说明限制；不接受任意 JSONPath。Policy 保存完整主范围和阶段范围定义，内部 Scope 不提供独立目录或写入口。阶段通过稳定 UUID 寻址；范围、任务和历史结果使用 Policy 子路由，读取及编辑权限归属 Policy。设备组目录继续提供目标、限制和排除的选择来源。

普通目录只能从真实公开行模型推导，挂载时执行完整性检查将 `modelIdentity`、未投影模型引用 与实际成功响应的 `items` 对齐；`Projection<T>` 仍省略未选择字段。列表与统计的 `role` 不同，但必须引用同一个目录 owner。HTTP 制品只发布能力和模型，不包含 SQL、数据库角色或内部执行绑定。固定顺序历史、固定快照、资格扫描和引用列表另标注 `purpose` 与具体原因；DA 活跃配置属于普通目录。

`/api/v1/devices` 的 `registeredAt` 是首次成功主注册事务记录的 Unix 秒，支持范围、空值过滤与排序；重试和续证保持不变，缺少可信历史的记录保持 null。`serialNumber`、`hardwareUuid` 是仅过滤的历史定位选择器，只支持 `==`、`=in=` 及逻辑组合，沿用 Inventory 规范化和字段敏感权限。组合条件必须在同一设备的同一份可信采集证据中成立；多个上报不会拼接，重复硬件返回全部获授权候选且不重复计数。非硬件 OR 分支不要求硬件证据。

硬件定位包含仍保留的退管设备，普通 Inventory 保留清理不删除定位证据；已物理删除的设备不会复活。结果只用于选择原设备 ID，时间线仍需要原 `AuditRead` 权限，不据此自动关联、合并历史或继承身份。新安装定义不回填旧记录，不从证书时间或最近通信推测注册时间。

保存查询的 `definition.query.filter` 匹配规范化 RSQL 文本，表示字面内容匹配，不表示逻辑等价或蕴含。规范文本由原 AST formatter 在同一写事务生成查询投影；字段退役检查仍消费权威 AST。

## 从选定源码提交消费

前端需要升级时，由消费方选择完整后端 commit，在该 commit 的独立源码 checkout 中运行上述导出命令，再复制输出到前端的 `contracts/mdm/http-v1.json`。生成期间保持源码不变；若源码包含本地改动，不能将结果记作精确来自该 commit。后端工具不再从 Git 对象读取已提交 JSON，也不提供提取或来源回执校验入口。

消费方在自己的升级提交中保存契约快照，并记录源码仓库、完整 commit、生成入口和实际文件 SHA-256，随后生成类型/校验器并迁移消费者。SHA-256 用于校验复制内容，不单独证明源码来源；来源由选定提交的源码生成过程确认。新输出没有该后端 commit 中的已提交 Git blob，消费方下次升级时须同步调整旧 pin 的 blob/path 语义，不能把计算出的 blob 哈希当作后端已提交文件的证明。

前端现有快照及 pin 可以继续离线使用；正常安装、开发、测试和构建仍只读取前端仓内输入，不自动访问后端、编译后端或追随 develop。仅契约升级需要生成和复制，本次后端变更不要求同步升级前端，也不引入制品发布服务。

## 现有独立制品

已有的 [`Collection.json`](../../crates/management-http/schema/Collection.json) 独立消费视图继续跟踪，由同一完整 HTTP 导出投影真实 request、response 和 query owner。其字段定义来自已挂载响应的 schema 引用闭包，不再维护第二份 Rust 类型清单或独立生成入口。查询投影表达当前实际 URL 参数。

```sh
# 仅维护 / 检查 Collection.json，不写完整 HTTP JSON。
python3 hack/http_contract_artifact.py --write
python3 hack/http_contract_artifact.py --check
```

`make ci` 的 `collection-schema` gate 仅比较真实挂载投影与 Collection 文件的字节；App 依赖闭包、工具和 Collection 输入变化会选中该检查。完整 HTTP JSON 没有提交漂移检查；schema 与引用校验仍在生成时执行。

其他重复的局部管理 HTTP schema 已由完整制品取代。Agent wire 生成器继续只负责纯协议制品，Webhook 材料的接收确认协议继续由 webhook owner 维护。`agent-wire` 不依赖 Axum、HTTP 契约包或服务端实现。

## 验证边界

实际函数签名与 extractor/response trait 绑定属于编译约束。schema 派生、引用闭合、挂载资源完整性与 Collection 漂移检查属于确定性检查；固定外部类型的适配器另有真实序列化接缝测试。授权、租户边界、签名、预算、恢复与实际 HTTP status 需要相应 T2 证据。离线导出和 schema 校验均不代表部署验收或真机验收。
