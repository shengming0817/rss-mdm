# 文档维护

文档只保留需要长期维护的需求、设计理由、操作与恢复知识或可追溯来源。修改行为时先判断是否影响这些内容；仅代码内部调整、测试补充或 issue 进度变化，不自动新增文档。

| 内容 | 唯一 owner |
| --- | --- |
| 产品需求、稳定 WMD/AC 编号、发布门 | docs/product/rss-mdm-prd.md |
| 工程方向与依赖波次 | docs/product/project-goals.md、roadmap.md |
| 跨模块职责、取舍与决策原因 | docs/architecture；ADR 保留决定及替代关系 |
| 长期用户/开发操作与失败恢复 | docs/guides、docs/deployment 的任务指南 |
| 公共类型/函数契约、字段与枚举 | 源码 rustdoc、schema；不手抄第二份类型表 |
| 版本、依赖、配置与预算数值 | manifest/lock、配置、源码；文档链接权威输入 |
| 过程、实现计划、测试结果、审查与处置清单 | issue/PR；不入库，不复制到 reference |
| 历史快照、外部来源、许可与不可再生验收证据 | docs/reference、对应 fixtures/reference 来源说明 |

新增前先搜索现有 owner，优先更新或合并。长期文档使用稳定任务名称，目录 README 只导航；crate README 说明职责并指向 rustdoc/任务指南。已结束实施计划直接删除，有效设计理由并入其 owner，不保留重定向占位或通过整篇搬到 reference 规避清理。

历史来源必须有来源、恢复方式与证据限制；保留许可证、摘要及引用锚点。历史判断不冒充当前状态，运行记录不随当前实现改写。需求/验收编号保持稳定，实质变更说明原因与影响。

完成变更检查链接、引用、diff 与忽略范围。处置清单和本次测试记录写入 PR，临时日志不入库。
