# Apple 采集协议 fixtures

人工构造的脱敏 SecurityInfo 响应，分别表达 Intel、T2、Apple silicon 的字段差异，不是生产 Mac 验收记录。恢复材料仅为测试哨兵，不是真实密钥。

来源：apple/device-management @ 09f249a06e7e3289930bf6d05f38fb562f748ebf，mdm/commands/information.security.yaml；编译输入、摘要和版本归档由 crates/native-schema/sources.json 持有。测试先验证固定原生 schema，再验证普通资产投影的去敏与缺席语义；T3 硬件支持矩阵由独立产品任务验收。
