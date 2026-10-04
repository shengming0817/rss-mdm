# Agent 协议

`enroll` 持有 `/api/v1/agent/enroll` 生命周期 DTO、schema 清单和指纹；`runtime` 持有 `/api/v1/agent/runtime` 消费的运行 JSON。HTTP、运行 wireVersion、capability 和任务签名域统一为新 V1；两族仍各自持有契约 owner。新 V1 继承当前 V6 的闭合输入、执行上下文和逐步骤结果，不兼容历史 V1 shape。共享包保持 publish=false，客户端固定消费同一完整 Git rev。

只有当前合同，没有旧模块别名或版本解码。秘密只用于一次性授权，业务认证由服务端真实 mTLS 证据持有。运行绑定回执使用 `runtime::BindingProfile`，包含 server-owned DeviceId、registration、generation、epoch 和冻结 collections；生命周期激活回执嵌入该 profile。

`hack/agent_wire_artifact.py --write` 刷新嵌入的任务定义及两个独立 schema 指纹；不带参数验证清单、覆盖和规范嵌入。Rust T1 验证严格字段、版本、签名域和 schema 消费。

详见[Agent 接入指南](../../docs/guides/agent-integration.md)。
