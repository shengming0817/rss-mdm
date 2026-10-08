# Jamf Pro 参考材料

2026-10-08 按用户提供的本地材料导入，五份文件保持原始内容和文件名。API 文件来自 `jamf/api/`，数据库快照来自同批材料的 `jamfpro_schema.sql`；克隆本仓即可取得全部文件，无需原本地目录。

- [API 概览](api/jamf-pro-api-summary.md)：分类导航。
- [API 分类参考](api/jamf-pro-api-classified.md)：按功能查找接口。
- [API 原始参考汇编](api/jamf-pro-api-reference.md)：来源文档的合并文本。
- [OpenAPI schema](api/api-schema.json)：OpenAPI 3.0.1，版本字段为 `production`，不能据此确定 Jamf Pro 产品版本。
- [数据库 schema](jamfpro_schema.sql)：MySQL DDL 快照，用于核对表、字段和约束；导出工具和数据库版本不代表 Jamf Pro 产品版本。

这些材料用于设备关联、资产及 API 的设计对标，不代表当前 Jamf 最新行为或 rss-mdm 已实现能力。分类与概览用于定位，具体接口和字段以原始材料为据；数据库 DDL 本身不能证明运行时匹配、授权或刷新算法。SQL 仅作参考，不纳入 rss-mdm 数据库初始化或迁移。

原文件中的来源链接、声明与示例原样保留。API schema 的 `info.termsOfService` 指向 [Jamf API License Agreement](https://www.jamf.com/developer-resources/api-license-agreement/)；本仓的收录不改变原材料的权利归属或适用条款。

## 原始文件摘要

摘要标识本次收录的固定版本；从其他来源恢复材料时应核对。

| 文件 | SHA-256 |
| --- | --- |
| [api/api-schema.json](api/api-schema.json) | `b592484b0f9a4f6edacd854627cb32fa2f4a210ad78ebf1395b771be3da3c207` |
| [api/jamf-pro-api-classified.md](api/jamf-pro-api-classified.md) | `f4db9ac88345b3e9b3b36e2c2991f1c25c3e8bb0afa79397cb462ee75b5a781a` |
| [api/jamf-pro-api-reference.md](api/jamf-pro-api-reference.md) | `34f8d0b17ad501ad3a8aa07ce8f2221266ecd5b6a59f574766de4e74641cfbab` |
| [api/jamf-pro-api-summary.md](api/jamf-pro-api-summary.md) | `47950621981850c1d60f87e48bebab5f7ef975d653f80c4b5068cb675153d286` |
| [jamfpro_schema.sql](jamfpro_schema.sql) | `4b04c7daba186a16589dbf1f15869502dabb8dc1043fd8e9bdc7cf58a1c4e872` |
