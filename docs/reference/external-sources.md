# 外部参考来源

以下为原 PRD 所列的官方参考资料及摘要，原记录访问日期为 2026-09-07；本次整理未重新验证在线内容。实施时应核对实际依赖版本、授权与平台限制，不能把资料摘要当作产品已验证能力。

<a id="e01"></a>

## E01　Jamf Pro：Policies

策略可组合脚本、账户、软件、触发器、频率与 Scope；用于产品行为对标。

[官方资料](https://learn.jamf.com/r/en-US/jamf-pro-documentation-11.20.0/Policies)

<a id="e02"></a>

## E02　Jamf Pro：Computer Configuration Profiles

配置描述文件与脚本型管理任务分别建模；支持创建或上传配置。

[官方资料](https://learn.jamf.com/r/en-US/jamf-pro-documentation-11.27.0/Computer_Configuration_Profiles)

<a id="e03"></a>

## E03　Jamf Pro：Extension Attribute Input Types

手工输入及脚本采集是不同属性来源；脚本解释器与输出格式有要求。

[官方资料](https://learn.jamf.com/r/en-US/jamf-pro-documentation-11.21.0/Extension_Attribute_Input_Types_macOS)

<a id="e04"></a>

## E04　Jamf Pro：Computer Extension Attributes

扩展属性可参与智能组与配置变量；不据此承诺本产品拥有 Jamf 全套能力。

[官方资料](https://learn.jamf.com/r/en-US/jamf-pro-documentation-11.21.0/Computer_Extension_Attributes)

<a id="e05"></a>

## E05　NanoMDM README

极简 Apple MDM server/library；明确不含完整 SCEP、TLS、ADE API、注册 profile、VPP 和自动业务编排。

[官方资料](https://github.com/micromdm/nanomdm/blob/main/README.md)

<a id="e06"></a>

## E06　NanoMDM Operations Guide

设备/用户 enrollment 标识、APNs、Plist 命令、回调及 DDM 请求转发；转发不等于 DDM 控制面。

[官方资料](https://github.com/micromdm/nanomdm/blob/main/docs/operations-guide.md)

<a id="e07"></a>

## E07　Fleet：Deploy software

官方部署指南标记 Fleet Premium；区分维护目录、自定义包与 App Store/VPP 应用。

[官方资料](https://fleetdm.com/guides/deploy-software-packages)

<a id="e08"></a>

## E08　Fleet：Reports

计划/即时 SQL 查询；离线主机不会回答即时查询。

[官方资料](https://fleetdm.com/guides/queries)

<a id="e09"></a>

## E09　Fleet：Automations

策略结果可以触发自动化；软件/脚本自动化有版本授权边界，不能等同于原生配置下发。

[官方资料](https://fleetdm.com/guides/automations)

<a id="e10"></a>

## E10　Fleet：Custom host vitals

自定义设备字段可用于脚本、配置变量和标签；与自动采集原始字段不同。

[官方资料](https://fleetdm.com/guides/custom-host-vitals)

<a id="e11"></a>

## E11　Fleet：Declarative device management primer

DDM 作为 Apple 管理能力；对标声明式配置与异步状态反馈。

[官方资料](https://fleetdm.com/articles/declarative-device-management-a-primer)

<a id="e12"></a>

## E12　Apple：Device Management

原生命令、查询、Check-in 与声明式管理的官方协议入口。

[官方资料](https://developer.apple.com/documentation/devicemanagement)

<a id="e13"></a>

## E13　Apple：Use declarative device management

声明、激活、资产与状态；设备和用户通道分别启用；注意与旧配置的冲突及优先级。

[官方资料](https://support.apple.com/guide/deployment/declarative-device-management-manage-apple-depc30268577/web)

<a id="e14"></a>

## E14　Apple：Privacy Preferences Policy Control

PPPC 受 OS、监督状态、具体权限类型约束；不能把有 root 权限等同于获得所有隐私权限。

[官方资料](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)

<a id="e15"></a>

## E15　Apple：Manage FileVault with device management

FileVault 管理与用户交互前提；不能直接复制 BitLocker 实现。

[官方资料](https://support.apple.com/guide/deployment/manage-filevault-with-device-management-dep0a2cb7686/web)

<a id="e16"></a>

## E16　Apple：Secure token, bootstrap token and volume ownership

Secure Token、Bootstrap Token 和 volume ownership 有不同语义；硬件/版本影响更新与擦除权限。

[官方资料](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web)

<a id="e17"></a>

## E17　Apple：Configure devices to work with APNs

APNs 与网络、证书依赖；推送用于提示设备联系管理服务，不是业务执行回执。

[官方资料](https://support.apple.com/guide/deployment/configure-devices-to-work-with-apns-dep2de55389a/web)

<a id="e18"></a>

## E18　Apple：MDM Vendor CSR Signing Certificate

生产 MDM Push Certificate 涉及 Vendor CSR 签名资质或受信签名服务；不能由普通 TLS 证书替代。

[官方资料](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/)

<a id="e19"></a>

## E19　Microsoft：Use WinGet

WinGet 客户端安装、发现、升级、移除；用户登录/注册会影响可用性。

[官方资料](https://learn.microsoft.com/en-us/windows/package-manager/winget/)

<a id="e20"></a>

## E20　Microsoft：WinGet source command

源的增删、更新等客户端管理；服务端发布流程不是 source 命令自动提供。

[官方资料](https://learn.microsoft.com/en-us/windows/package-manager/winget/source)

<a id="e21"></a>

## E21　Microsoft：winget-cli-restsource

官方 REST Source 参考实现；示例使用 Azure/CosmosDB，不代表私有化产品必须依赖 Azure。

[官方资料](https://github.com/microsoft/winget-cli-restsource)

<a id="e22"></a>

## E22　Homebrew：Taps

Tap 为 Git 来源，包含 Formula/Cask；源码及脚本存在信任边界。

[官方资料](https://docs.brew.sh/Taps)

<a id="e23"></a>

## E23　Homebrew：Create and Maintain a Tap

私有 Tap 的标准目录与维护入口；用于复用生态格式。

[官方资料](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap)

<a id="e24"></a>

## E24　Homebrew：Formula bottle API

bottle 支持自定义 root_url 及架构/系统标签、哈希；元数据源与产物源须分别管理。

[官方资料](https://docs.brew.sh/rubydoc/Formula.html)

<a id="e25"></a>

## E25　Homebrew：FAQ

默认设计偏单用户；常规包操作不应直接作为 root 执行。

[官方资料](https://docs.brew.sh/FAQ)

<a id="e26"></a>

## E26　Homebrew：Manpage

当前文档含 as-console-user；必须按实际客户端版本检测，不能假设所有旧版本存在。

[官方资料](https://docs.brew.sh/Manpage)

<a id="e27"></a>

## E27　Homebrew 6.0.0 release notes（2026-06-11）

该版本增加 Cask pin、as-console-user 与显式 Tap trust，并公布 Intel 支持变化；按实际客户端和架构冻结矩阵。

[官方资料](https://brew.sh/2026/06/11/homebrew-6.0.0/)

<a id="e28"></a>

## E28　Homebrew：Installation

Apple Silicon / Intel 的默认前缀与支持条件不同；自定义前缀需独立验证。

[官方资料](https://docs.brew.sh/Installation)

<a id="e29"></a>

## E29　osquery：Remote Settings

远程配置、日志与分布式查询接口；复用查询机制，不实现第二套查询语言。

[官方资料](https://osquery.readthedocs.io/en/stable/deployment/remote/)

<a id="e30"></a>

## E30　osquery：Configuration

Query pack、计划、平台/版本发现等能力；采集计划需约束预算与兼容性。

[官方资料](https://osquery.readthedocs.io/en/stable/deployment/configuration/)

<a id="e31"></a>

## E31　osquery 官方项目说明

跨平台表与扩展接口；并非所有表在所有 OS 相同。

[官方资料](https://github.com/osquery/osquery)

<a id="e32"></a>

## E32　Apple：Device Information command

原生资产查询有通道和版本条件；仅映射支持字段。

[官方资料](https://developer.apple.com/documentation/devicemanagement/device-information-command)

<a id="e33"></a>

## E33　Apple：Installed Application List command

原生应用清单不等于 Homebrew 的 Formula/Cask 依赖数据库。

[官方资料](https://developer.apple.com/documentation/devicemanagement/installed-application-list-command)

<a id="e34"></a>

## E34　Fleet：Custom variables in scripts and profiles

全局变量与逐设备值不同；借鉴分离模型，不复制其秘密注入策略。

[官方资料](https://fleetdm.com/guides/secrets-in-scripts-and-configuration-profiles)
