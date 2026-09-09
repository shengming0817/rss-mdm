# REST Source 1.0 fixtures

`upstream-exe.json` 原样提取 Microsoft winget-cli commit
`c17eadbcacf2f5244b13de0d563d921c33ac4af6` 的
`src/AppInstallerCLITests/RestInterface_1_0.cpp::GetGoodManifest_RequiredFields` JSON 字符串。
`upstream-information.json` 原样来自同 commit 的
`src/AppInstallerCLIE2ETests/TestData/TestRestSource/information`。
Copyright (c) Microsoft Corporation. Licensed under the MIT License；许可证见 LICENSE-Microsoft.txt。

`msi.json` 为 RSS 自有受控 MSI 样本，按同一官方结构构造，不是端侧安装证明。
`provenance.json` 记录各样本字节摘要；行为断言在 protocol.rs，真实 HTTP 边界在 t2_http.rs。
