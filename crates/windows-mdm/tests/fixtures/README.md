# Windows MDM V1 协议样本

本目录是 T1 数据，不是真机抓包或生产凭据。`provenance.json` 固定官方来源的 URL、获取 UTC、原始下载字节摘要，以及各 XML 的摘要。HTML 摘要标识本次读取，网页以后变化不自动升级协议。

历史归档 `winmdm20260220-develop.zip` SHA-256 为 `bb08749e671080dd96a3d61dd31c662730604cd288303fa67e7917aaf9778e67`；恢复方式见仓库 `reference/README.md`。

| 样本 | 来源与改写 |
|---|---|
| initialization.xml、results.xml | 历史 `src/pkg/syncml/parser_test.go` 的 `samplePkg1` / `samplePkg3` 内联合成样本；设备、主机名、厂商、型号和序列号替换为 TEST/Example 值。 |
| initialization-login-status.xml | MS-MDM §4 Protocol Examples 的完整 package #1；保留官方示例占位值及 1224 LoginStatus，仅 HTML entity 解码、NBSP 转空格和提取首个 SyncML 文档。来源下载摘要与 XML 摘要见 provenance.json。 |
| discovery-response.xml | 历史 `src/pkg/mde/discovery.go` 响应模板；填入测试关联 ID/URL，移除非 V1 diagnostics ActivityId。 |
| policy-response.xml | 历史 `src/pkg/xcep/policy.go` 模板；测试关联 ID 和显式策略数值；review 按 MS-MDE2 官方示例改为 SHA-256 的 OID 2.16.840.1.101.3.4.2.1、group 1（算法组，修正旧样本的签名组误用）、szOID_NIST_sha256，删除历史 SHA-1 OID 的错误命名。 |
| issue-response.xml | 历史 `src/pkg/wstep/wstep.go` 外层 RSTRC 模板；固定测试时间，provisioning 为字节 01 02 03，完全不代表有效证书或 provisioning 文档。 |
| discovery-request.xml | 按 MS-MDE2 Discover 的 xsd:all 独立编写，含必需 OSEdition/AuthPolicies，固定 On-Premise/4.0/CIMClient_Windows 配置。 |
| get.xml、status-details.xml | 按 MS-MDM Get 与 Status 内容模型独立编写，Status 含 Data 后的 Item 和 TargetRef。 |
| fault-*.xml | 独立固定五种 Code/Subcode 与产品公开安全 Reason；恶意外部 Reason 由测试变异生成。 |
| policy-request.xml、issue-request.xml | 按 MS-MDE2 On-Premise 章节独立编写；TEST-USER/TEST-SECRET 是合成标记，CSR 是字节 01 02 03。 |

协议解析与输出以固定规范为准，不继承历史实现的 local-name 容错、重复覆盖或 deviceID 信任行为。SOAP golden 比较使用独立 namespace-aware XML 事件投影，不调用产品 codec 生成预期结果。大型攻击样本在测试中生成。
