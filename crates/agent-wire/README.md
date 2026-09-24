# rss-mdm-agent-wire

服务端与独立 Agent 共享的闭合 wire 协议。公共契约由 [源码与 rustdoc](src/lib.rs) 持有，使用流程见 [任务指南](../../docs/guides/agent-integration.md)。

版本化 JSON schema、规范样本和指纹由 [schemas](schema) 及 tests 持有。仅共享协议值类型，不依赖服务端 domain/PG；生产者和接收者都执行闭合输入检查。
