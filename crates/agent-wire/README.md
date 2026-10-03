# Agent 协议

`enroll` 持有 `/api/agent/enroll/v1` 生命周期 DTO、schema 清单和指纹；`runtime` 持有 `/api/agent/runtime/v1` 消费的运行 JSON。HTTP API 各自版本为 1，运行 payloadVersion 保持 6，capability 和签名域仍为 v6。

只有当前合同，没有旧模块别名或版本解码。秘密只用于一次性授权，业务认证由服务端真实 mTLS 证据持有。运行绑定回执使用 `runtime::BindingProfile`，包含 server-owned DeviceId、registration、generation、epoch 和冻结 collections；生命周期激活回执嵌入该 profile。

`hack/agent_wire_artifact.py --write` 刷新嵌入的任务定义及两个独立 schema 指纹；不带参数验证清单、覆盖和规范嵌入。Rust T1 验证严格字段、版本、签名域和 schema 消费。

详见[Agent 接入指南](../../docs/guides/agent-integration.md)。
