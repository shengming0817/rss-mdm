# rss-mdm-software-release

精确版本到实际目标的直接发布与结果决策。公共契约由 [源码与 rustdoc](src/lib.rs) 持有，使用流程见 [任务指南](../../docs/guides/resources-and-software.md)。

## 来源

- [Tough Target](https://github.com/awslabs/tough/blob/98d8eb8b2ce63515d9b4981c938ef6453c5b5771/tough/src/schema/mod.rs#L432-L500)：精确产物摘要；借鉴内容绑定，不引入 TUF 网络/验签协议。
- [in-toto Step](https://github.com/in-toto/in-toto-rs/blob/48e57fd04624d30d081fae1dddf56caaa4a5b81e/src/models/layout/step.rs#L92-L110)：证据与参与者约束一起绑定；真实身份和验证由产品 owner 提供。
- 历史 WinMDM `src/internal/domain/resource/{entity,value_object}.go` 和 `src/internal/application/resource/service.go` 仅作缺口证据，不继承无 tenant、可变版本 detail 或系统时钟。来源与恢复见 [reference/README](../../reference/README.md)。

完整平台版本与一次 WinGet manifest / Brew document 发布一一对应；平台变体、依赖与材料共同固定，避免分架构提交造成内容不完整或撤回误删。
