# REST Source 1.0 fixtures

`upstream-exe.json` 原样提取 Microsoft winget-cli commit
`c17eadbcacf2f5244b13de0d563d921c33ac4af6` 的
`src/AppInstallerCLITests/RestInterface_1_0.cpp::GetGoodManifest_RequiredFields` JSON 字符串。
`upstream-information.json` 原样来自同 commit 的
`src/AppInstallerCLIE2ETests/TestData/TestRestSource/information`。
Copyright (c) Microsoft Corporation. Licensed under the MIT License；许可证见 LICENSE-Microsoft.txt。

`msi.json` 为 RSS 自有受控 MSI 样本，按同一官方结构构造，不是端侧安装证明。
`provenance.json` 记录各样本字节摘要；行为断言在 protocol.rs，真实 HTTP 边界在 t2_http.rs。

`publish-schema.json` 抽取 Microsoft winget-cli-restsource
`21cd5dda3dab39aa059f4d34914959736af7ee70` 的
`documentation/WinGet-1.0.0.yaml` 中 ManifestSchema 的 44 项依赖闭包。
保留约束与本地引用，去除说明文字，OpenAPI nullable 显式转为 JSON Schema null union。
`publication_schema.rs` 使用成熟 jsonschema 验证器检验真实发布输出，包含错误包装和缺必填字段反例。
该依赖仅用于 crate 测试，不进入独立产品 normal closure。

可选再生：在临时 Python venv 安装 `PyYAML==6.0.3`，运行本目录 `extract-publish-schema.py`；
脚本核对固定上游字节摘要。正常 CI 直接消费已提交 JSON，无 PyYAML/网络 schema 依赖。
