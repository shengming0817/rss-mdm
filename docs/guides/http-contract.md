# HTTP 契约与固定提交消费

完整自有管理 HTTP 与 Agent API 制品位于 [`contracts/http-v1.json`](../../contracts/http-v1.json)。格式为 V1，schema 使用 JSON Schema 2020-12。App 的离线导出复用生产的路由注册、路径组合、配置静态路径及条件挂载，不启动服务、不连接数据库、不构造虚假服务状态。

受保护端点的 `authentication` 引用实际管理认证 owner；`alternatives` 为互斥凭据方式，各自包含 header schema、必填 header 和限制。Cookie 的写请求要求 Origin、`X-Identity-Request: 1` 和 session 绑定的 CSRF，GET/HEAD 使用被动认证；Bearer/API key 仅在实际允许的入口出现。`conditional_response_headers` 描述 401 的 `WWW-Authenticate` 条件，不能作为每个 401 都必含该 header 的承诺。描述在最终路径组合后解析，租户管理及自助入口保留实际凭据限制。

## 生成与工作区检查

```sh
python3 hack/http_contract_artifact.py --write
python3 hack/http_contract_artifact.py --check
```

命令使用现有构建 lease 和 Cargo 缓存，允许工作区包含尚未提交的改动。检查比较当前真实 handler 派生结果与制品字节，不能用制品自己的摘要替代漂移检查。`make ci` 的 `http-contract-artifact` gate 执行相同检查；影响选择覆盖 App 依赖闭包和制品工具输入。

`apps/server/examples/http_contract.rs` 是产品组合层入口。`http-contract` 只描述注册到 Axum 的实际参数与响应类型；不执行第二套 extractor、handler 或 middleware。查询 owner 同时提供参数声明和实际解析入口，保留原授权与延迟解析顺序。

## 制品结构

- `endpoints` 按 listener、method、path 排序。`operationId` 为 `listener:METHOD:path`，`handler` 保留实际 Rust handler 来源。
- `request` 包含 path、query、body 和 headers。body 同时声明媒体类型；`required_headers` 记录实际必需 header。响应按实际 HTTP status、媒体类型、body 和 header 描述，错误使用真实 HTTP 投影，不导出内部错误枚举作为回包。
- 每个 schema 描述含 `direction` 与 `schemaId`。`schemas[schemaId]` 是独立的 schema 根；其中 `#/$defs/...` 必须相对于该根解析。请求按 deserialize、响应按 serialize 派生，省略字段与显式 null 不等同。二进制、范围下载、压缩入口、数值编码继续由原传输 owner 执行。
- `conditions` 表示真实条件挂载。完整导出包含这些条件下的端点全集；条件名称不是部署能力探测或版本握手。`agent_listener` 要求产品实际启用 Agent listener；各服务条件仍由生产装配决定。
- `configuredPath` 描述配置绑定的静态 UUID 路径段。例如 management tenant 路径保留生产中静态路由优先于普通捕获路由的语义，记录配置来源及被覆盖的 operation，不写入某个部署的 UUID。
- `external` 标记已挂载的 Apple/Windows/软件仓库原生协议入口，`externalOwners` 记录 Identity SDK 边界。平台模块中的自有管理和 Agent 接口仍属于 `endpoints`。原生状态叶子等明确的外部协议数据由其原 owner 校验，不能据此放开核心身份、动作或状态结构。

Schema 中的 `x-rss-extension` 仅标识具体扩展位置及其 owner，例如 Resource 输出、展示元数据、Apple 已验证的原生 status 叶子。它不表示整个响应可接受任意 JSON。动态字段和列表仍由 Inventory/用户 schema 解释。

## 从固定 Git 对象提取

消费方独立选择完整的 40 位小写 commit。仓库 HEAD 可以前移，工作区可以变脏；提取只读取指定 commit 中的 Git blob，正常提取不需要 Cargo、相邻源码检出或重新生成。

```sh
# REV 填入消费方独立选定的完整 commit；不是 HEAD、分支名或短 SHA。
REV='<full-40-character-commit>'
python3 /path/to/http_contract_artifact.py \
  --repository /path/to/rss-mdm \
  --extract "$REV" --output ./http-v1.json
python3 /path/to/http_contract_artifact.py \
  --repository /path/to/rss-mdm \
  --verify-source "$REV" --input ./http-v1.json
```

工具可以单独复制使用。消费方的 Git 对象库须已获取该提交；其获取与信任来源由消费方控制。输出 `http-v1.json.source.json` 记录实际 commit、制品路径、Git blob 身份及内容 SHA-256。验证必须再次针对独立传入的 revision，从 Git 对象读取并比较内容和回执。重算摘要、修改回执或仅相信文件自报 revision，均不能证明来源。

错误 revision、非 commit、缺失 blob、未知格式/方言、重复键、重复路由/operation、未绑定 schema 和未解析引用均明确失败。仓库制品不嵌入当前 commit，不产生自引用提交，也不引入 registry、打包发布服务、启动拒绝或自动升级机制。

## 现有独立制品

Web 已有的 [`Collection.json`](../../crates/management-http/schema/Collection.json) 独立消费视图保留，由同一完整 HTTP 导出投影真实 request、response 和 query owner。其字段定义来自已挂载响应的 schema 引用闭包，不再维护第二份 Rust 类型清单或独立生成入口。查询投影表达当前实际 URL 参数；固定在旧 commit 的消费者继续从旧 Git 对象读取原版本。

其他重复的局部管理 HTTP schema 已由完整制品取代。Agent wire 生成器继续只负责纯协议制品，Webhook 材料的接收确认协议继续由 webhook owner 维护。`agent-wire` 不依赖 Axum、HTTP 契约包或服务端实现。

## 验证边界

实际函数签名与 extractor/response trait 绑定属于编译约束。schema 派生、引用闭合、挂载资源完整性、漂移与 Git 来源检查属于确定性检查；固定外部类型的适配器另有真实序列化接缝测试。授权、租户边界、签名、预算、恢复与实际 HTTP status 需要相应 T2 证据。离线导出和 schema 校验均不代表部署验收或真机验收。
