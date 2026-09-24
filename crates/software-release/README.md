# rss-mdm-software-release

不可变候选、分环审批与发布结果决策。公共契约由 [源码与 rustdoc](src/lib.rs) 持有，使用流程见 [任务指南](../../docs/guides/resources-and-software.md)。

## 来源

- [Tough Target](https://github.com/awslabs/tough/blob/98d8eb8b2ce63515d9b4981c938ef6453c5b5771/tough/src/schema/mod.rs#L432-L500)：精确产物摘要；借鉴内容绑定，不引入 TUF 网络/验签协议。
- [in-toto Step](https://github.com/in-toto/in-toto-rs/blob/48e57fd04624d30d081fae1dddf56caaa4a5b81e/src/models/layout/step.rs#L92-L110)：证据与参与者约束一起绑定；真实身份和验证由产品 owner 提供。
- 历史 WinMDM `src/internal/domain/resource/{entity,value_object}.go` 和 `src/internal/application/resource/service.go` 仅作缺口证据，不继承无 tenant、可变版本 detail 或系统时钟。来源与恢复见 [reference/README](../../docs/README.md)。

#2389 直接替换原单 variant 内容模型，不提供 V1 发布身份兼容路径；PG 持久化只接收当前模型。完整平台版本与一次 WinGet manifest / Brew document 发布一一对应，避免分架构审批造成未批准内容发布或撤回误删。
