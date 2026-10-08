# Jamf Pro API 概览

> 本文档为 [jamf-pro-api-classified.md](jamf-pro-api-classified.md) 的索引摘要，共 1441 个 API 端点，分为 21 个功能类别。

---

## 分类总览

| 分类 | 端点数 | 链接 |
|------|--------|------|
| 认证与安全 | 108 | [查看详情](jamf-pro-api-classified.md#认证与安全) |
| 用户与账户管理 | 122 | [查看详情](jamf-pro-api-classified.md#用户与账户管理) |
| 设备注册与管理 | 90 | [查看详情](jamf-pro-api-classified.md#设备注册与管理) |
| MDM与设备通信 | 23 | [查看详情](jamf-pro-api-classified.md#mdm与设备通信) |
| 计算机管理 | 192 | [查看详情](jamf-pro-api-classified.md#计算机管理) |
| 移动设备管理 | 159 | [查看详情](jamf-pro-api-classified.md#移动设备管理) |
| 应用与软件管理 | 96 | [查看详情](jamf-pro-api-classified.md#应用与软件管理) |
| 配置文件与策略 | 38 | [查看详情](jamf-pro-api-classified.md#配置文件与策略) |
| 补丁管理 | 137 | [查看详情](jamf-pro-api-classified.md#补丁管理) |
| 内容分发与VPP | 52 | [查看详情](jamf-pro-api-classified.md#内容分发与vpp) |
| 搜索与报告 | 76 | [查看详情](jamf-pro-api-classified.md#搜索与报告) |
| 脚本与自动化 | 29 | [查看详情](jamf-pro-api-classified.md#脚本与自动化) |
| 自助服务 | 21 | [查看详情](jamf-pro-api-classified.md#自助服务) |
| 云服务与集成 | 58 | [查看详情](jamf-pro-api-classified.md#云服务与集成) |
| 组织结构与分类 | 69 | [查看详情](jamf-pro-api-classified.md#组织结构与分类) |
| 网络与基础设施 | 74 | [查看详情](jamf-pro-api-classified.md#网络与基础设施) |
| 外围设备与打印 | 39 | [查看详情](jamf-pro-api-classified.md#外围设备与打印) |
| 医疗与定位服务 | 15 | [查看详情](jamf-pro-api-classified.md#医疗与定位服务) |
| 教育管理 | 12 | [查看详情](jamf-pro-api-classified.md#教育管理) |
| 系统配置 | 30 | [查看详情](jamf-pro-api-classified.md#系统配置) |
| 文件上传 | 1 | [查看详情](jamf-pro-api-classified.md#文件上传) |
| **合计** | **1441** | |

---

## 认证与安全 (108 个端点) [↗](jamf-pro-api-classified.md#认证与安全)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| allowedfileextensions | 5 | [查看](jamf-pro-api-classified.md#allowedfileextensions) |
| auth | 8 | [查看](jamf-pro-api-classified.md#auth) |
| conditional-access | 3 | [查看](jamf-pro-api-classified.md#conditional-access) |
| diskencryptionconfigurations | 8 | [查看](jamf-pro-api-classified.md#diskencryptionconfigurations) |
| jsonwebtokenconfigurations | 5 | [查看](jamf-pro-api-classified.md#jsonwebtokenconfigurations) |
| local-admin-password | 12 | [查看](jamf-pro-api-classified.md#local-admin-password) |
| oauth | 1 | [查看](jamf-pro-api-classified.md#oauth) |
| oauth2 | 1 | [查看](jamf-pro-api-classified.md#oauth2) |
| oidc | 6 | [查看](jamf-pro-api-classified.md#oidc) |
| pki | 35 | [查看](jamf-pro-api-classified.md#pki) |
| slasa | 2 | [查看](jamf-pro-api-classified.md#slasa) |
| sso | 15 | [查看](jamf-pro-api-classified.md#sso) |
**External Patch Source API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| auth | 4 | [查看](jamf-pro-api-classified.md#auth) |
| codesigning | 3 | [查看](jamf-pro-api-classified.md#codesigning) |

## 用户与账户管理 (122 个端点) [↗](jamf-pro-api-classified.md#用户与账户管理)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| account-preferences | 4 | [查看](jamf-pro-api-classified.md#account-preferences) |
| accounts | 19 | [查看](jamf-pro-api-classified.md#accounts) |
| api-integrations | 6 | [查看](jamf-pro-api-classified.md#api-integrations) |
| api-role-privileges | 2 | [查看](jamf-pro-api-classified.md#api-role-privileges) |
| api-roles | 5 | [查看](jamf-pro-api-classified.md#api-roles) |
| classic-ldap | 1 | [查看](jamf-pro-api-classified.md#classic-ldap) |
| cloud-ldaps | 11 | [查看](jamf-pro-api-classified.md#cloud-ldaps) |
| directorybindings | 8 | [查看](jamf-pro-api-classified.md#directorybindings) |
| jssuser | 1 | [查看](jamf-pro-api-classified.md#jssuser) |
| ldap | 5 | [查看](jamf-pro-api-classified.md#ldap) |
| ldap-keystore | 1 | [查看](jamf-pro-api-classified.md#ldap-keystore) |
| ldapservers | 14 | [查看](jamf-pro-api-classified.md#ldapservers) |
| smart-user-groups | 1 | [查看](jamf-pro-api-classified.md#smart-user-groups) |
| static-user-groups | 2 | [查看](jamf-pro-api-classified.md#static-user-groups) |
| user | 7 | [查看](jamf-pro-api-classified.md#user) |
| userextensionattributes | 8 | [查看](jamf-pro-api-classified.md#userextensionattributes) |
| usergroups | 8 | [查看](jamf-pro-api-classified.md#usergroups) |
| users | 12 | [查看](jamf-pro-api-classified.md#users) |
**External Patch Source API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| users | 7 | [查看](jamf-pro-api-classified.md#users) |

## 设备注册与管理 (90 个端点) [↗](jamf-pro-api-classified.md#设备注册与管理)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| adue-session-token-settings | 2 | [查看](jamf-pro-api-classified.md#adue-session-token-settings) |
| device-enrollments | 14 | [查看](jamf-pro-api-classified.md#device-enrollments) |
| devices | 1 | [查看](jamf-pro-api-classified.md#devices) |
| enrollment | 15 | [查看](jamf-pro-api-classified.md#enrollment) |
| enrollment-customization | 17 | [查看](jamf-pro-api-classified.md#enrollment-customization) |
| enrollment-customizations | 10 | [查看](jamf-pro-api-classified.md#enrollment-customizations) |
| onboarding | 8 | [查看](jamf-pro-api-classified.md#onboarding) |
| reenrollment | 5 | [查看](jamf-pro-api-classified.md#reenrollment) |
| return-to-service | 5 | [查看](jamf-pro-api-classified.md#return-to-service) |
| service-discovery-enrollment | 2 | [查看](jamf-pro-api-classified.md#service-discovery-enrollment) |
| supervision-identities | 7 | [查看](jamf-pro-api-classified.md#supervision-identities) |
| v4 | 4 | [查看](jamf-pro-api-classified.md#v4) |

## MDM与设备通信 (23 个端点) [↗](jamf-pro-api-classified.md#mdm与设备通信)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| apns-client-push-status | 4 | [查看](jamf-pro-api-classified.md#apns-client-push-status) |
| check-in | 4 | [查看](jamf-pro-api-classified.md#check-in) |
| deploy-package | 1 | [查看](jamf-pro-api-classified.md#deploy-package) |
| device-communication-settings | 4 | [查看](jamf-pro-api-classified.md#device-communication-settings) |
| jamf-management-framework | 1 | [查看](jamf-pro-api-classified.md#jamf-management-framework) |
| mdm | 5 | [查看](jamf-pro-api-classified.md#mdm) |
| mdm-renewal | 4 | [查看](jamf-pro-api-classified.md#mdm-renewal) |

## 计算机管理 (192 个端点) [↗](jamf-pro-api-classified.md#计算机管理)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| computer-extension-attributes | 13 | [查看](jamf-pro-api-classified.md#computer-extension-attributes) |
| computer-groups | 12 | [查看](jamf-pro-api-classified.md#computer-groups) |
| computer-inventory | 2 | [查看](jamf-pro-api-classified.md#computer-inventory) |
| computer-inventory-collection-settings | 8 | [查看](jamf-pro-api-classified.md#computer-inventory-collection-settings) |
| computer-prestages | 10 | [查看](jamf-pro-api-classified.md#computer-prestages) |
| computercheckin | 2 | [查看](jamf-pro-api-classified.md#computercheckin) |
| computercommands | 5 | [查看](jamf-pro-api-classified.md#computercommands) |
| computerextensionattributes | 8 | [查看](jamf-pro-api-classified.md#computerextensionattributes) |
| computergroups | 8 | [查看](jamf-pro-api-classified.md#computergroups) |
| computerhardwaresoftwarereports | 10 | [查看](jamf-pro-api-classified.md#computerhardwaresoftwarereports) |
| computerhistory | 10 | [查看](jamf-pro-api-classified.md#computerhistory) |
| computerinventorycollection | 2 | [查看](jamf-pro-api-classified.md#computerinventorycollection) |
| computerinvitations | 7 | [查看](jamf-pro-api-classified.md#computerinvitations) |
| computermanagement | 25 | [查看](jamf-pro-api-classified.md#computermanagement) |
| computerreports | 3 | [查看](jamf-pro-api-classified.md#computerreports) |
| computers | 26 | [查看](jamf-pro-api-classified.md#computers) |
| computers-inventory | 33 | [查看](jamf-pro-api-classified.md#computers-inventory) |
| computers-inventory-detail | 6 | [查看](jamf-pro-api-classified.md#computers-inventory-detail) |
| preview | 1 | [查看](jamf-pro-api-classified.md#preview) |
| smart-computer-groups | 1 | [查看](jamf-pro-api-classified.md#smart-computer-groups) |

## 移动设备管理 (159 个端点) [↗](jamf-pro-api-classified.md#移动设备管理)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| devices | 1 | [查看](jamf-pro-api-classified.md#devices) |
| mobile-device-enrollment-profile | 1 | [查看](jamf-pro-api-classified.md#mobile-device-enrollment-profile) |
| mobile-device-extension-attributes | 8 | [查看](jamf-pro-api-classified.md#mobile-device-extension-attributes) |
| mobile-device-groups | 13 | [查看](jamf-pro-api-classified.md#mobile-device-groups) |
| mobile-device-prestages | 28 | [查看](jamf-pro-api-classified.md#mobile-device-prestages) |
| mobile-devices | 9 | [查看](jamf-pro-api-classified.md#mobile-devices) |
| mobiledevicecommands | 6 | [查看](jamf-pro-api-classified.md#mobiledevicecommands) |
| mobiledeviceconfigurationprofiles | 10 | [查看](jamf-pro-api-classified.md#mobiledeviceconfigurationprofiles) |
| mobiledeviceenrollmentprofiles | 13 | [查看](jamf-pro-api-classified.md#mobiledeviceenrollmentprofiles) |
| mobiledeviceextensionattributes | 8 | [查看](jamf-pro-api-classified.md#mobiledeviceextensionattributes) |
| mobiledevicegroups | 8 | [查看](jamf-pro-api-classified.md#mobiledevicegroups) |
| mobiledevicehistory | 10 | [查看](jamf-pro-api-classified.md#mobiledevicehistory) |
| mobiledeviceinvitations | 7 | [查看](jamf-pro-api-classified.md#mobiledeviceinvitations) |
| mobiledeviceprovisioningprofiles | 13 | [查看](jamf-pro-api-classified.md#mobiledeviceprovisioningprofiles) |
| mobiledevices | 23 | [查看](jamf-pro-api-classified.md#mobiledevices) |
| smart-mobile-device-groups | 1 | [查看](jamf-pro-api-classified.md#smart-mobile-device-groups) |

## 应用与软件管理 (96 个端点) [↗](jamf-pro-api-classified.md#应用与软件管理)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| app-request | 8 | [查看](jamf-pro-api-classified.md#app-request) |
| app-store-country-codes | 1 | [查看](jamf-pro-api-classified.md#app-store-country-codes) |
| computerapplications | 4 | [查看](jamf-pro-api-classified.md#computerapplications) |
| computerapplicationusage | 5 | [查看](jamf-pro-api-classified.md#computerapplicationusage) |
| licensedsoftware | 8 | [查看](jamf-pro-api-classified.md#licensedsoftware) |
| macapplications | 10 | [查看](jamf-pro-api-classified.md#macapplications) |
| macos-managed-software-updates | 2 | [查看](jamf-pro-api-classified.md#macos-managed-software-updates) |
| managed-software-updates | 16 | [查看](jamf-pro-api-classified.md#managed-software-updates) |
| mobile-device-apps | 1 | [查看](jamf-pro-api-classified.md#mobile-device-apps) |
| mobiledeviceapplications | 16 | [查看](jamf-pro-api-classified.md#mobiledeviceapplications) |
| restrictedsoftware | 8 | [查看](jamf-pro-api-classified.md#restrictedsoftware) |
| volume-purchasing-locations | 10 | [查看](jamf-pro-api-classified.md#volume-purchasing-locations) |
| volume-purchasing-subscriptions | 7 | [查看](jamf-pro-api-classified.md#volume-purchasing-subscriptions) |

## 配置文件与策略 (38 个端点) [↗](jamf-pro-api-classified.md#配置文件与策略)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| byoprofiles | 8 | [查看](jamf-pro-api-classified.md#byoprofiles) |
| ddm | 3 | [查看](jamf-pro-api-classified.md#ddm) |
| dss-declarations | 1 | [查看](jamf-pro-api-classified.md#dss-declarations) |
| osxconfigurationprofiles | 10 | [查看](jamf-pro-api-classified.md#osxconfigurationprofiles) |
| policies | 12 | [查看](jamf-pro-api-classified.md#policies) |
| policy-properties | 2 | [查看](jamf-pro-api-classified.md#policy-properties) |
| settings | 2 | [查看](jamf-pro-api-classified.md#settings) |

## 补丁管理 (137 个端点) [↗](jamf-pro-api-classified.md#补丁管理)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| patch-management-accept-disclaimer | 1 | [查看](jamf-pro-api-classified.md#patch-management-accept-disclaimer) |
| patch-policies | 11 | [查看](jamf-pro-api-classified.md#patch-policies) |
| patch-software-title-configurations | 17 | [查看](jamf-pro-api-classified.md#patch-software-title-configurations) |
| patchavailabletitles | 1 | [查看](jamf-pro-api-classified.md#patchavailabletitles) |
| patches | 10 | [查看](jamf-pro-api-classified.md#patches) |
| patchexternalsources | 8 | [查看](jamf-pro-api-classified.md#patchexternalsources) |
| patchinternalsources | 3 | [查看](jamf-pro-api-classified.md#patchinternalsources) |
| patchpolicies | 7 | [查看](jamf-pro-api-classified.md#patchpolicies) |
| patchreports | 2 | [查看](jamf-pro-api-classified.md#patchreports) |
| patchsoftwaretitles | 5 | [查看](jamf-pro-api-classified.md#patchsoftwaretitles) |
**External Patch Source API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| available | 1 | [查看](jamf-pro-api-classified.md#available) |
| capabilities | 2 | [查看](jamf-pro-api-classified.md#capabilities) |
| components | 6 | [查看](jamf-pro-api-classified.md#components) |
| criteria | 2 | [查看](jamf-pro-api-classified.md#criteria) |
| extensionattributes | 4 | [查看](jamf-pro-api-classified.md#extensionattributes) |
| killapps | 4 | [查看](jamf-pro-api-classified.md#killapps) |
| overrides | 4 | [查看](jamf-pro-api-classified.md#overrides) |
| patches | 11 | [查看](jamf-pro-api-classified.md#patches) |
| preferences | 3 | [查看](jamf-pro-api-classified.md#preferences) |
| privileges | 1 | [查看](jamf-pro-api-classified.md#privileges) |
| requirements | 2 | [查看](jamf-pro-api-classified.md#requirements) |
| softwaretitles | 10 | [查看](jamf-pro-api-classified.md#softwaretitles) |
| sources | 5 | [查看](jamf-pro-api-classified.md#sources) |
| subscribed | 9 | [查看](jamf-pro-api-classified.md#subscribed) |
| valuelists | 8 | [查看](jamf-pro-api-classified.md#valuelists) |

## 内容分发与VPP (52 个端点) [↗](jamf-pro-api-classified.md#内容分发与vpp)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| ebooks | 13 | [查看](jamf-pro-api-classified.md#ebooks) |
| jamf-package | 2 | [查看](jamf-pro-api-classified.md#jamf-package) |
| packages | 21 | [查看](jamf-pro-api-classified.md#packages) |
| vppaccounts | 5 | [查看](jamf-pro-api-classified.md#vppaccounts) |
| vppassignments | 5 | [查看](jamf-pro-api-classified.md#vppassignments) |
| vppinvitations | 6 | [查看](jamf-pro-api-classified.md#vppinvitations) |

## 搜索与报告 (76 个端点) [↗](jamf-pro-api-classified.md#搜索与报告)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| advanced-mobile-device-searches | 7 | [查看](jamf-pro-api-classified.md#advanced-mobile-device-searches) |
| advanced-user-content-searches | 5 | [查看](jamf-pro-api-classified.md#advanced-user-content-searches) |
| advancedcomputersearches | 8 | [查看](jamf-pro-api-classified.md#advancedcomputersearches) |
| advancedmobiledevicesearches | 8 | [查看](jamf-pro-api-classified.md#advancedmobiledevicesearches) |
| advancedusersearches | 8 | [查看](jamf-pro-api-classified.md#advancedusersearches) |
| dashboard | 2 | [查看](jamf-pro-api-classified.md#dashboard) |
| inventory-information | 1 | [查看](jamf-pro-api-classified.md#inventory-information) |
| inventory-preload | 34 | [查看](jamf-pro-api-classified.md#inventory-preload) |
| savedsearches | 3 | [查看](jamf-pro-api-classified.md#savedsearches) |

## 脚本与自动化 (29 个端点) [↗](jamf-pro-api-classified.md#脚本与自动化)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| commandflush | 2 | [查看](jamf-pro-api-classified.md#commandflush) |
| scheduler | 3 | [查看](jamf-pro-api-classified.md#scheduler) |
| scripts | 16 | [查看](jamf-pro-api-classified.md#scripts) |
| webhooks | 8 | [查看](jamf-pro-api-classified.md#webhooks) |

## 自助服务 (21 个端点) [↗](jamf-pro-api-classified.md#自助服务)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| branding-images | 1 | [查看](jamf-pro-api-classified.md#branding-images) |
| login-customization | 2 | [查看](jamf-pro-api-classified.md#login-customization) |
| self-service | 15 | [查看](jamf-pro-api-classified.md#self-service) |
| self-service-plus | 3 | [查看](jamf-pro-api-classified.md#self-service-plus) |

## 云服务与集成 (58 个端点) [↗](jamf-pro-api-classified.md#云服务与集成)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| cloud-azure | 6 | [查看](jamf-pro-api-classified.md#cloud-azure) |
| cloud-idp | 8 | [查看](jamf-pro-api-classified.md#cloud-idp) |
| cloud-information | 1 | [查看](jamf-pro-api-classified.md#cloud-information) |
| csa | 3 | [查看](jamf-pro-api-classified.md#csa) |
| impact-alert-notification-settings | 2 | [查看](jamf-pro-api-classified.md#impact-alert-notification-settings) |
| jamf-connect | 7 | [查看](jamf-pro-api-classified.md#jamf-connect) |
| jamf-protect | 10 | [查看](jamf-pro-api-classified.md#jamf-protect) |
| jamf-remote-assist | 5 | [查看](jamf-pro-api-classified.md#jamf-remote-assist) |
| parent-app | 4 | [查看](jamf-pro-api-classified.md#parent-app) |
| preview | 12 | [查看](jamf-pro-api-classified.md#preview) |

## 组织结构与分类 (69 个端点) [↗](jamf-pro-api-classified.md#组织结构与分类)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| buildings | 18 | [查看](jamf-pro-api-classified.md#buildings) |
| categories | 16 | [查看](jamf-pro-api-classified.md#categories) |
| departments | 16 | [查看](jamf-pro-api-classified.md#departments) |
| groups | 4 | [查看](jamf-pro-api-classified.md#groups) |
| icon | 3 | [查看](jamf-pro-api-classified.md#icon) |
| locales | 1 | [查看](jamf-pro-api-classified.md#locales) |
| sites | 10 | [查看](jamf-pro-api-classified.md#sites) |
| time-zones | 1 | [查看](jamf-pro-api-classified.md#time-zones) |

## 网络与基础设施 (74 个端点) [↗](jamf-pro-api-classified.md#网络与基础设施)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| cache-settings | 2 | [查看](jamf-pro-api-classified.md#cache-settings) |
| cloud-distribution-point | 11 | [查看](jamf-pro-api-classified.md#cloud-distribution-point) |
| distribution-points | 9 | [查看](jamf-pro-api-classified.md#distribution-points) |
| distributionpoints | 8 | [查看](jamf-pro-api-classified.md#distributionpoints) |
| gsx-connection | 6 | [查看](jamf-pro-api-classified.md#gsx-connection) |
| gsxconnection | 2 | [查看](jamf-pro-api-classified.md#gsxconnection) |
| infrastructuremanager | 3 | [查看](jamf-pro-api-classified.md#infrastructuremanager) |
| jcds | 6 | [查看](jamf-pro-api-classified.md#jcds) |
| networksegments | 8 | [查看](jamf-pro-api-classified.md#networksegments) |
| smtp-server | 5 | [查看](jamf-pro-api-classified.md#smtp-server) |
| smtpserver | 2 | [查看](jamf-pro-api-classified.md#smtpserver) |
| softwareupdateservers | 8 | [查看](jamf-pro-api-classified.md#softwareupdateservers) |
**External Patch Source API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| smtpserver | 4 | [查看](jamf-pro-api-classified.md#smtpserver) |

## 外围设备与打印 (39 个端点) [↗](jamf-pro-api-classified.md#外围设备与打印)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| dock-items | 4 | [查看](jamf-pro-api-classified.md#dock-items) |
| dockitems | 8 | [查看](jamf-pro-api-classified.md#dockitems) |
| peripherals | 6 | [查看](jamf-pro-api-classified.md#peripherals) |
| peripheraltypes | 5 | [查看](jamf-pro-api-classified.md#peripheraltypes) |
| printers | 8 | [查看](jamf-pro-api-classified.md#printers) |
| removablemacaddresses | 8 | [查看](jamf-pro-api-classified.md#removablemacaddresses) |

## 医疗与定位服务 (15 个端点) [↗](jamf-pro-api-classified.md#医疗与定位服务)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| healthcarelistener | 3 | [查看](jamf-pro-api-classified.md#healthcarelistener) |
| healthcarelistenerrule | 4 | [查看](jamf-pro-api-classified.md#healthcarelistenerrule) |
| ibeacons | 8 | [查看](jamf-pro-api-classified.md#ibeacons) |

## 教育管理 (12 个端点) [↗](jamf-pro-api-classified.md#教育管理)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| classes | 8 | [查看](jamf-pro-api-classified.md#classes) |
| teacher-app | 4 | [查看](jamf-pro-api-classified.md#teacher-app) |

## 系统配置 (30 个端点) [↗](jamf-pro-api-classified.md#系统配置)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| activation-code | 5 | [查看](jamf-pro-api-classified.md#activation-code) |
| activationcode | 2 | [查看](jamf-pro-api-classified.md#activationcode) |
| health-check | 1 | [查看](jamf-pro-api-classified.md#health-check) |
| health-status | 1 | [查看](jamf-pro-api-classified.md#health-status) |
| jamf-pro-information | 1 | [查看](jamf-pro-api-classified.md#jamf-pro-information) |
| jamf-pro-server-url | 4 | [查看](jamf-pro-api-classified.md#jamf-pro-server-url) |
| jamf-pro-version | 1 | [查看](jamf-pro-api-classified.md#jamf-pro-version) |
| log-flushing | 5 | [查看](jamf-pro-api-classified.md#log-flushing) |
| logflush | 3 | [查看](jamf-pro-api-classified.md#logflush) |
| notifications | 2 | [查看](jamf-pro-api-classified.md#notifications) |
| settings | 1 | [查看](jamf-pro-api-classified.md#settings) |
| startup-status | 1 | [查看](jamf-pro-api-classified.md#startup-status) |
| system | 3 | [查看](jamf-pro-api-classified.md#system) |

## 文件上传 (1 个端点) [↗](jamf-pro-api-classified.md#文件上传)

**Jamf Pro API**

| 资源 | 端点数 | 链接 |
|------|--------|------|
| fileuploads | 1 | [查看](jamf-pro-api-classified.md#fileuploads) |
