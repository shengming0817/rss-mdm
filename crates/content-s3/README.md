# rss-mdm-content-s3

产品内部 S3 内容适配，向软件内容仓提供对象和分片操作；不拥有业务授权、引用、批准、数据库提交或清理资格。

公共接口与恢复结果由源码 rustdoc 持有。生产消费者接线归 #2664；本项不改变现有文件内容仓。

历史来源：RSS commit `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`（tag `baseline/pre-community-core-20260902`），`adapters/s3/src/store.rs`、`dlx_archive.rs` 和 `private_ca.rs`。仅提取下载流、条件创建、精确版本与私有 CA 的实现经验，不继承旧 API、DI/runtime 或 DLX/WORM 职责。

上游：[AWS Rust SDK 分片完成源码](https://github.com/awslabs/aws-sdk-rust/blob/e3a8e3db1bd094e96c0e707f15e6f38baf92fe07/sdk/s3/src/operation/complete_multipart_upload/builders.rs)、[S3 条件创建](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)、[分片校验语义](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)。SDK 精确版本由 Cargo manifest/lock 持有。

连接、秘密引用及恢复操作见[本地开发](../../docs/guides/local-development.md#s3-内容适配)；实际 provider 与验证边界见[测试模块](../../docs/guides/test-modules.md#s3-内容适配验证)。

RustFS 1.0.0 的 [ListParts 映射](https://github.com/rustfs/rustfs/blob/d47f54bfb2f39f48bd1adda334bd27e151fe85b8/rustfs/src/storage/s3_api/multipart.rs) 不返回可选分片摘要；状态明确保留未知值。完整对象仍强制通过精确版本的长度/SHA-256 流式回读。
