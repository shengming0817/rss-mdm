# Jamf Pro API 分类参考手册

> 本文档包含 1441 个 API 端点，按功能分为 21 个类别。

> 源文件声明 1521 个条目，其中 80 个为资源分类描述（无 API 定义），实际有效端点为 1441 个。


## 目录

- [认证与安全](#认证与安全) (108 个端点)
- [用户与账户管理](#用户与账户管理) (122 个端点)
- [设备注册与管理](#设备注册与管理) (90 个端点)
- [MDM与设备通信](#MDM与设备通信) (23 个端点)
- [计算机管理](#计算机管理) (192 个端点)
- [移动设备管理](#移动设备管理) (159 个端点)
- [应用与软件管理](#应用与软件管理) (96 个端点)
- [配置文件与策略](#配置文件与策略) (38 个端点)
- [补丁管理](#补丁管理) (137 个端点)
- [内容分发与VPP](#内容分发与VPP) (52 个端点)
- [搜索与报告](#搜索与报告) (76 个端点)
- [脚本与自动化](#脚本与自动化) (29 个端点)
- [自助服务](#自助服务) (21 个端点)
- [云服务与集成](#云服务与集成) (58 个端点)
- [组织结构与分类](#组织结构与分类) (69 个端点)
- [网络与基础设施](#网络与基础设施) (74 个端点)
- [外围设备与打印](#外围设备与打印) (39 个端点)
- [医疗与定位服务](#医疗与定位服务) (15 个端点)
- [教育管理](#教育管理) (12 个端点)
- [系统配置](#系统配置) (30 个端点)
- [文件上传](#文件上传) (1 个端点)

---

## 认证与安全

### Jamf Pro API

#### allowedfileextensions

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/allowedfileextensions` | Finds the allowed file extensions |
| `GET` | `/allowedfileextensions/extension/{extension}` | Finds an allowed file extension value by name |
| `GET` | `/allowedfileextensions/id/{id}` | Finds an allowed file extension value by ID |
| `POST` | `/allowedfileextensions/id/{id}` | Creates a new allowed file extension value by ID |
| `DELETE` | `/allowedfileextensions/id/{id}` | Deletes an allowed file extension value by ID |

#### auth

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/auth` | Get all the Authorization details associated with the current api
 |
| `POST` | `/auth/current` | Get the authorization details associated with the current API token
 |
| `POST` | `/auth/invalidateToken` | Invalidate current token
 |
| `POST` | `/auth/keepAlive` | Invalidate existing token and generates new token
 |
| `GET` | `/v1/auth` | Get all the Authorization details associated with the current api
 |
| `POST` | `/v1/auth/invalidate-token` | Invalidate current token
 |
| `POST` | `/v1/auth/keep-alive` | Invalidate existing token and generates new token
 |
| `POST` | `/v1/auth/token` | Create a token based on other authentication details (basic, etc.) |

#### conditional-access

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/conditional-access/device-compliance-information/computer/{deviceId}` | Get compliance information for a single computer device |
| `GET` | `/v1/conditional-access/device-compliance-information/mobile/{deviceId}` | Get compliance information for a single mobile device |
| `GET` | `/v1/conditional-access/device-compliance/feature-toggle` | Retrieves Status of the Feature Toggle |

#### diskencryptionconfigurations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/diskencryptionconfigurations` | Finds all disk encryption configurations |
| `GET` | `/diskencryptionconfigurations/id/{id}` | Finds disk encryption configurations by ID |
| `POST` | `/diskencryptionconfigurations/id/{id}` | Creates a new disk encryption configuration by ID |
| `PUT` | `/diskencryptionconfigurations/id/{id}` | Updates an existing disk encryption configuration by ID |
| `DELETE` | `/diskencryptionconfigurations/id/{id}` | Deletes a disk encryption configuration by ID |
| `GET` | `/diskencryptionconfigurations/name/{name}` | Finds disk encryption configurations by name |
| `PUT` | `/diskencryptionconfigurations/name/{name}` | Updates an existing disk encryption configuration by name |
| `DELETE` | `/diskencryptionconfigurations/name/{name}` | Deletes a disk encryption configuration by name |

#### jsonwebtokenconfigurations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/jsonwebtokenconfigurations` | Finds all JSON Web Token configurations |
| `GET` | `/jsonwebtokenconfigurations/id/{id}` | Find JSON Web Token configuration by ID |
| `POST` | `/jsonwebtokenconfigurations/id/{id}` | Creates a new JSON Web Token configuration by ID |
| `PUT` | `/jsonwebtokenconfigurations/id/{id}` | Updates an existing JSON Web Token configuration by ID |
| `DELETE` | `/jsonwebtokenconfigurations/id/{id}` | Deletes a JSON Web Token configuration by ID |

#### local-admin-password

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/local-admin-password/pending-rotations` | Get a list of the current devices and usernames with pending LAPS rotations |
| `GET` | `/v2/local-admin-password/settings` | Get the current LAPS settings. |
| `PUT` | `/v2/local-admin-password/settings` | Update settings for LAPS. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/account/{username}/audit` | Get LAPS password viewed history. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/account/{username}/history` | Get LAPS historical records for target device and username. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/account/{username}/password` | Get current LAPS password for specified username on a client. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/account/{username}/{guid}/audit` | Get LAPS password viewed history. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/account/{username}/{guid}/history` | Get LAPS historical records for target device and user guid. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/account/{username}/{guid}/password` | Get current LAPS password for specified user guid on a client. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/accounts` | Get the LAPS capable admin accounts for a device. |
| `GET` | `/v2/local-admin-password/{clientManagementId}/history` | Get LAPS password viewed history, and rotation history. |
| `PUT` | `/v2/local-admin-password/{clientManagementId}/set-password` | Set the LAPS password for a device. |

#### oauth

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/oauth/token` | Obtain an access token using an API Client |

#### oauth2

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/oauth2/session-tokens` | Retrieve the access token and user information for the current session.
 |

#### oidc

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/oidc/direct-idp-login-url` | Retrieve the URL to directly login to the IdP
 |
| `POST` | `/v1/oidc/dispatch` | Provide the url to redirect for OIDC login |
| `POST` | `/v1/oidc/generate-certificate` | Generate a new keystore used for signing OIDC messages
 |
| `GET` | `/v1/oidc/public-features` | Get the public features of the OIDC configuration |
| `GET` | `/v1/oidc/public-key` | Get the public key of the keystore used for signing OIDC messages as a JWT
 |
| `POST` | `/v2/oidc/dispatch` | Provide the url to redirect for OIDC login |

#### pki

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/pki/adcs-settings` | Create AD CS Settings configuration for either inbound or outbound mode
 |
| `POST` | `/v1/pki/adcs-settings/validate-certificate` | Validate AD CS Settings server certificate
 |
| `POST` | `/v1/pki/adcs-settings/validate-client-certificate` | Validate AD CS Settings client certificate
 |
| `GET` | `/v1/pki/adcs-settings/{id}` | Get AD CS Settings configuration for the ID value
 |
| `PATCH` | `/v1/pki/adcs-settings/{id}` | Update AD CS Settings configuration
 |
| `DELETE` | `/v1/pki/adcs-settings/{id}` | Delete AD CS Settings configuration by ID
 |
| `GET` | `/v1/pki/adcs-settings/{id}/dependencies` | Retrieve list of AD CS Settings dependencies |
| `GET` | `/v1/pki/adcs-settings/{id}/history` | Get specified AD CS Settings history object
 |
| `POST` | `/v1/pki/adcs-settings/{id}/history` | Add specified AD CS Settings object note
 |
| `GET` | `/v1/pki/certificate-authority/active` | Returns X.509 details of the active Certificate Authority (CA) |
| `GET` | `/v1/pki/certificate-authority/active/der` | Returns X.509 of active Certificate Authority (CA) in DER format |
| `GET` | `/v1/pki/certificate-authority/active/pem` | Returns active Certificate Authority (CA) in PEM format |
| `GET` | `/v1/pki/certificate-authority/{id}` | Returns X.509 details of Certificate Authority (CA) with provided ID |
| `GET` | `/v1/pki/certificate-authority/{id}/der` | Returns X.509 current Certificate Authority (CA) with provided ID in DER format |
| `GET` | `/v1/pki/certificate-authority/{id}/pem` | Returns current Certificate Authority (CA) with provided ID in PEM format |
| `POST` | `/v1/pki/digicert/trust-lifecycle-manager` | Create DigiCert Trust Lifecycle Manager configuration with client authentication via client certificate.
 |
| `POST` | `/v1/pki/digicert/trust-lifecycle-manager/validate-client-certificate` | Validate DigiCert Trust Lifecycle Manager client certificate
 |
| `GET` | `/v1/pki/digicert/trust-lifecycle-manager/{id}` | Retrieve DigiCert Trust Lifecycle Manager configuration |
| `PATCH` | `/v1/pki/digicert/trust-lifecycle-manager/{id}` | Update DigiCert Trust Lifecycle Manager configuration
 |
| `DELETE` | `/v1/pki/digicert/trust-lifecycle-manager/{id}` | Delete DigiCert Trust Lifecycle Manager configuration |
| `GET` | `/v1/pki/digicert/trust-lifecycle-manager/{id}/connection-status` | Get connection status of DigiCert Trust Lifecycle Manager for a given ID |
| `GET` | `/v1/pki/digicert/trust-lifecycle-manager/{id}/dependencies` | Retrieve list of DigiCert Trust Lifecycle Manager Settings dependencies |
| `POST` | `/v1/pki/venafi` | Create a PKI configuration in Jamf Pro for Venafi
 |
| `GET` | `/v1/pki/venafi/{id}` | Retrieve a Venafi PKI configuration from Jamf Pro
 |
| `PATCH` | `/v1/pki/venafi/{id}` | Update a Venafi PKI configuration in Jamf Pro
 |
| `DELETE` | `/v1/pki/venafi/{id}` | Delete a Venafi PKI configuration from Jamf Pro
 |
| `GET` | `/v1/pki/venafi/{id}/connection-status` | Tests the communication between Jamf Pro and a Jamf Pro PKI Proxy Server
 |
| `GET` | `/v1/pki/venafi/{id}/dependent-profiles` | Get configuration profile data using specified Venafi CA object
 |
| `GET` | `/v1/pki/venafi/{id}/history` | Get specified Venafi CA history object
 |
| `POST` | `/v1/pki/venafi/{id}/history` | Add specified Venafi CA Object Note
 |
| `GET` | `/v1/pki/venafi/{id}/jamf-public-key` | Downloads a certificate used to secure communication between Jamf Pro and a Jamf Pro PKI Proxy Server
 |
| `POST` | `/v1/pki/venafi/{id}/jamf-public-key/regenerate` | Regenerates a certificate used to secure communication between Jamf Pro and a Jamf Pro PKI Proxy Server
 |
| `GET` | `/v1/pki/venafi/{id}/proxy-trust-store` | Downloads the PKI Proxy Server public key to secure communication between Jamf Pro and a Jamf Pro PKI Proxy Server
 |
| `POST` | `/v1/pki/venafi/{id}/proxy-trust-store` | Uploads the PKI Proxy Server public key to secure communication between Jamf Pro and a Jamf Pro PKI Proxy Server
 |
| `DELETE` | `/v1/pki/venafi/{id}/proxy-trust-store` | Removes the PKI Proxy Server public key used to secure communication between Jamf Pro and a Jamf Pro PKI Proxy Server
 |

#### slasa

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/slasa` | Get the status of SLASA |
| `POST` | `/v1/slasa` | Accept the SLASA |

#### sso

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/sso/failover` | Retrieve the current failover settings |
| `POST` | `/v1/sso/failover/generate` | Regenerates failover url |
| `GET` | `/v2/sso/cert` | Retrieve the certificate currently configured for use with SSO
 |
| `POST` | `/v2/sso/cert` | Jamf Pro will generate a new certificate and use it to sign SSO
 |
| `PUT` | `/v2/sso/cert` | Update the certificate used by Jamf Pro to sign SSO requests to the identify provider
 |
| `DELETE` | `/v2/sso/cert` | Delete the currently configured certificate used by SSO
 |
| `GET` | `/v2/sso/cert/download` | Download the certificate currently configured for use with Jamf Pro's SSO configuration
 |
| `POST` | `/v2/sso/cert/parse` | Parse the certificate to get details about certificate type and keys needed to upload certificate file
 |
| `GET` | `/v3/sso` | Retrieve the current Single Sign On configuration settings
 |
| `PUT` | `/v3/sso` | Updates the current Single Sign On configuration settings
 |
| `GET` | `/v3/sso/dependencies` | Retrieve the list of Enrollment Customizations using SSO
 |
| `POST` | `/v3/sso/disable` | Disable SSO
 |
| `GET` | `/v3/sso/history` | Get SSO history object
 |
| `POST` | `/v3/sso/history` | Add SSO history object notes
 |
| `GET` | `/v3/sso/metadata/download` | Download the Jamf Pro SAML metadata file
 |

### External Patch Source API

#### auth

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/auth/current` | Get token claims |
| `POST` | `/auth/keepalive` | Refresh token |
| `POST` | `/auth/recover` | Send token |
| `POST` | `/auth/tokens` | Create token |

#### codesigning

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/codesigning/certificate` | Get certificate info |
| `PUT` | `/codesigning/certificate` | Update certificate |
| `DELETE` | `/codesigning/certificate` | Delete certificate |

---

## 用户与账户管理

### Jamf Pro API

#### account-preferences

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/account-preferences` | Get Jamf Pro account preferences
 |
| `PATCH` | `/v2/account-preferences` | Update Jamf Pro account preferences
 |
| `GET` | `/v3/account-preferences` | Get Jamf Pro account preferences
 |
| `PATCH` | `/v3/account-preferences` | Update Jamf Pro account preferences
 |

#### accounts

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/accounts` | Finds all accounts |
| `GET` | `/accounts/groupid/{id}` | Finds groups by ID |
| `POST` | `/accounts/groupid/{id}` | Creates a new group by ID |
| `PUT` | `/accounts/groupid/{id}` | Updates an existing group by ID |
| `DELETE` | `/accounts/groupid/{id}` | Deletes a group by ID |
| `GET` | `/accounts/groupname/{name}` | Finds groups by name |
| `PUT` | `/accounts/groupname/{name}` | Updates an existing group by name |
| `DELETE` | `/accounts/groupname/{name}` | Deletes a group by name |
| `GET` | `/accounts/userid/{id}` | Finds accounts by ID |
| `POST` | `/accounts/userid/{id}` | Creates a new account by ID |
| `PUT` | `/accounts/userid/{id}` | Updates an existing account by ID |
| `DELETE` | `/accounts/userid/{id}` | Deletes an account by ID |
| `GET` | `/accounts/username/{name}` | Finds accounts by name |
| `PUT` | `/accounts/username/{name}` | Updates an existing account by name |
| `DELETE` | `/accounts/username/{name}` | Deletes an account by name |
| `GET` | `/v1/accounts` | Get user accounts |
| `POST` | `/v1/accounts` | Adds new account.
 |
| `GET` | `/v1/accounts/{id}` | Gets the user account.
 |
| `DELETE` | `/v1/accounts/{id}` | Deletes the user account.
 |

#### api-integrations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/api-integrations` | Get the current API Integrations |
| `POST` | `/v1/api-integrations` | Create API integration object |
| `GET` | `/v1/api-integrations/{id}` | Get specified API integration object |
| `PUT` | `/v1/api-integrations/{id}` | Update specified API integration object |
| `DELETE` | `/v1/api-integrations/{id}` | Remove specified API integration |
| `POST` | `/v1/api-integrations/{id}/client-credentials` | Create client credentials for specified API integration |

#### api-role-privileges

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/api-role-privileges` | Get the current Jamf API Role Privileges |
| `GET` | `/v1/api-role-privileges/search` | Search the current Jamf API Role Privileges |

#### api-roles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/api-roles` | Get the current Jamf API Roles |
| `POST` | `/v1/api-roles` | Create a new API role |
| `GET` | `/v1/api-roles/{id}` | Get the specific Jamf API Role |
| `PUT` | `/v1/api-roles/{id}` | Update API Integrations Role |
| `DELETE` | `/v1/api-roles/{id}` | Delete API Integrations Role |

#### classic-ldap

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/classic-ldap/{id}` | Get mappings for OnPrem Ldap configuration with given id. |

#### cloud-ldaps

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v2/cloud-ldaps` | Create Cloud Identity Provider configuration |
| `GET` | `/v2/cloud-ldaps/defaults/{provider}/mappings` | Get default mappings |
| `GET` | `/v2/cloud-ldaps/defaults/{provider}/server-configuration` | Get default server configuration |
| `GET` | `/v2/cloud-ldaps/{id}` | Get Cloud Identity Provider configuration with given id. |
| `PUT` | `/v2/cloud-ldaps/{id}` | Update Cloud Identity Provider configuration |
| `DELETE` | `/v2/cloud-ldaps/{id}` | Delete Cloud Identity Provider configuration. |
| `GET` | `/v2/cloud-ldaps/{id}/connection/bind` | Get bind connection pool statistics |
| `GET` | `/v2/cloud-ldaps/{id}/connection/search` | Get search connection pool statistics |
| `GET` | `/v2/cloud-ldaps/{id}/connection/status` | Tests the communication with the specified cloud connection
 |
| `GET` | `/v2/cloud-ldaps/{id}/mappings` | Get mappings configurations for Cloud Identity Providers server configuration. |
| `PUT` | `/v2/cloud-ldaps/{id}/mappings` | Update Cloud Identity Provider mappings configuration. |

#### directorybindings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/directorybindings` | Finds all directory bindings |
| `GET` | `/directorybindings/id/{id}` | Finds directory bindings by ID |
| `POST` | `/directorybindings/id/{id}` | Creates a new directory binding by ID |
| `PUT` | `/directorybindings/id/{id}` | Updates an existing directory binding by ID |
| `DELETE` | `/directorybindings/id/{id}` | Deletes a directory binding by ID |
| `GET` | `/directorybindings/name/{name}` | Finds directory bindings by name |
| `PUT` | `/directorybindings/name/{name}` | Updates an existing directory binding by name |
| `DELETE` | `/directorybindings/name/{name}` | Deletes a directory binding by name |

#### jssuser

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/jssuser` | Returns basic information about Jamf Pro, as well as privileges of the person requesting the resource. (Deprecated) |

#### ldap

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/ldap/groups` | Retrieve the configured access groups that contain the text in the search param
 |
| `GET` | `/ldap/servers` | Retrieve all Servers including LDAP and Cloud Identity Providers.
 |
| `GET` | `/v1/ldap/groups` | Retrieve the configured access groups that contain the text in the search param
 |
| `GET` | `/v1/ldap/ldap-servers` | Retrieve all LDAP Servers.
 |
| `GET` | `/v1/ldap/servers` | Retrieve all Servers including LDAP and Cloud Identity Providers.
 |

#### ldap-keystore

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/ldap-keystore/verify` | Validate keystore for Cloud Identity Provider secure connection |

#### ldapservers

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/ldapservers` | Finds all LDAP servers |
| `GET` | `/ldapservers/id/{id}` | Finds LDAP servers by ID |
| `POST` | `/ldapservers/id/{id}` | Creates a new LDAP server by ID |
| `PUT` | `/ldapservers/id/{id}` | Updates an existing LDAP server by ID |
| `DELETE` | `/ldapservers/id/{id}` | Deletes an LDAP server by ID |
| `GET` | `/ldapservers/id/{id}/group/{group}` | Display information for matching groups for an LDAP server |
| `GET` | `/ldapservers/id/{id}/group/{group}/user/{user}` | Display information about user membership in a group for an LDAP server |
| `GET` | `/ldapservers/id/{id}/user/{user}` | Display information for matching users for an LDAP server |
| `GET` | `/ldapservers/name/{name}` | Finds LDAP servers by name |
| `PUT` | `/ldapservers/name/{name}` | Updates an existing LDAP server by name |
| `DELETE` | `/ldapservers/name/{name}` | Deletes an LDAP server by name |
| `GET` | `/ldapservers/name/{name}/group/{group}` | Display information for matching groups for an LDAP server |
| `GET` | `/ldapservers/name/{name}/group/{group}/user/{user}` | Display information about user membership in a group for an LDAP server |
| `GET` | `/ldapservers/name/{name}/user/{user}` | Display information for matching users for an LDAP server |

#### smart-user-groups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/smart-user-groups/{id}/recalculate` | Recalculate the smart group for the given id and then return the ids for the users in the smart group
 |

#### static-user-groups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/static-user-groups` | Return a list of all Static User Groups
 |
| `GET` | `/v1/static-user-groups/{id}` | Return a specific Static User Group by id
 |

#### user

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/user` | Return all Jamf Pro user acounts
 |
| `POST` | `/user/updateSession` | Update values in the User's current session
 |
| `POST` | `/v1/user/change-password` | Changes the user account password.
 |
| `GET` | `/v1/user/preferences/settings/{keyId}` | Get the user preferences for the authenticated user and key.
 |
| `GET` | `/v1/user/preferences/{keyId}` | Get the user setting for the authenticated user and key
 |
| `PUT` | `/v1/user/preferences/{keyId}` | Persist the user setting
 |
| `DELETE` | `/v1/user/preferences/{keyId}` | Remove specified setting for authenticated user
 |

#### userextensionattributes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/userextensionattributes` | Finds all user extension attributes |
| `GET` | `/userextensionattributes/id/{id}` | Finds user extension attributes by ID |
| `POST` | `/userextensionattributes/id/{id}` | Creates a new user extension attribute by ID |
| `PUT` | `/userextensionattributes/id/{id}` | Updates an existing user extension attribute by ID |
| `DELETE` | `/userextensionattributes/id/{id}` | Deletes a user extension attribute by ID |
| `GET` | `/userextensionattributes/name/{name}` | Finds user extension attributes by name |
| `PUT` | `/userextensionattributes/name/{name}` | Updates an existing user extension attribute by name |
| `DELETE` | `/userextensionattributes/name/{name}` | Deletes a user extension attribute by name |

#### usergroups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/usergroups` | Finds all user groups |
| `GET` | `/usergroups/id/{id}` | Finds user groups by ID |
| `POST` | `/usergroups/id/{id}` | Creates user groups by ID |
| `PUT` | `/usergroups/id/{id}` | Updates user groups by ID |
| `DELETE` | `/usergroups/id/{id}` | Deletes user groups by ID |
| `GET` | `/usergroups/name/{name}` | Finds user groups by name |
| `PUT` | `/usergroups/name/{name}` | Updates user groups by name |
| `DELETE` | `/usergroups/name/{name}` | Deletes user groups by name |

#### users

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/users` | Finds all users |
| `GET` | `/users/email/{email}` | Finds users by email address |
| `PUT` | `/users/email/{email}` | Updates an existing user by email address |
| `DELETE` | `/users/email/{email}` | Deletes a user by email address |
| `GET` | `/users/id/{id}` | Finds users by ID |
| `POST` | `/users/id/{id}` | Creates a new user by ID |
| `PUT` | `/users/id/{id}` | Updates an existing user by ID |
| `DELETE` | `/users/id/{id}` | Deletes a user by ID |
| `GET` | `/users/name/{name}` | Finds users by name |
| `PUT` | `/users/name/{name}` | Updates an existing user by name |
| `DELETE` | `/users/name/{name}` | Deletes a user by name |
| `POST` | `/v1/users/{id}/recalculate-smart-groups` | Recalculate a smart group for the given user id and then return the count of smart groups the user falls into
 |

### External Patch Source API

#### users

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/users` | Get users |
| `POST` | `/users` | Create user |
| `GET` | `/users/{id}` | Get user |
| `PUT` | `/users/{id}` | Update user |
| `DELETE` | `/users/{id}` | Delete user |
| `GET` | `/users/{id}/privileges` | Get privileges |
| `POST` | `/users/{id}/privileges` | Create privilege |

---

## 设备注册与管理

### Jamf Pro API

#### adue-session-token-settings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/adue-session-token-settings` | Retrieve the Account Driven User Enrollment Session Token Settings
 |
| `PUT` | `/v1/adue-session-token-settings` | Update Account Driven User Enrollment Session Token Settings.
 |

#### device-enrollments

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/device-enrollments` | Read all sorted and paged Device Enrollment instances
 |
| `GET` | `/v1/device-enrollments/public-key` | Retrieve the Jamf Pro Device Enrollment public key
 |
| `GET` | `/v1/device-enrollments/syncs` | Get all instance sync states for all Device Enrollment Instances
 |
| `POST` | `/v1/device-enrollments/upload-token` | Create a Device Enrollment Instance with the supplied Token
 |
| `GET` | `/v1/device-enrollments/{id}` | Retrieve a Device Enrollment Instance with the supplied id
 |
| `PUT` | `/v1/device-enrollments/{id}` | Update a Device Enrollment Instance with the supplied id
 |
| `DELETE` | `/v1/device-enrollments/{id}` | Delete a Device Enrollment Instance with the supplied id
 |
| `GET` | `/v1/device-enrollments/{id}/devices` | Retrieve a list of Devices assigned to the supplied id
 |
| `POST` | `/v1/device-enrollments/{id}/disown` | Disown devices from the given Device Enrollment Instance
 |
| `GET` | `/v1/device-enrollments/{id}/history` | Get sorted and paged Device Enrollment history objects
 |
| `POST` | `/v1/device-enrollments/{id}/history` | Add Device Enrollment history object notes
 |
| `GET` | `/v1/device-enrollments/{id}/syncs` | Get all instance sync states for a single Device Enrollment Instance
 |
| `GET` | `/v1/device-enrollments/{id}/syncs/latest` | Get the latest sync state for a single Device Enrollment Instance
 |
| `PUT` | `/v1/device-enrollments/{id}/upload-token` | Update a Device Enrollment Instance with the supplied Token
 |

#### devices

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/devices/{id}/groups` | Return a list of groups for a device
 |

#### enrollment

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/enrollment/history` | Get sorted and paged Enrollment history object
 |
| `POST` | `/v2/enrollment/history` | Add Enrollment history object notes
 |
| `POST` | `/v2/enrollment/history/export` | Export enrollment history collection
 |
| `GET` | `/v3/enrollment/access-groups` | Retrieve the configured LDAP groups configured for User-Initiated Enrollment.
 |
| `POST` | `/v3/enrollment/access-groups` | Add the configured LDAP group for User-Initiated Enrollment.
 |
| `GET` | `/v3/enrollment/access-groups/{id}` | Retrieve the configured LDAP groups configured for User-Initiated Enrollment
 |
| `PUT` | `/v3/enrollment/access-groups/{id}` | Modify the configured LDAP groups configured for User-Initiated Enrollment. Only exiting Access Groups can be updated.
 |
| `DELETE` | `/v3/enrollment/access-groups/{id}` | Delete an LDAP group's access to user initiated Enrollment.
 |
| `GET` | `/v3/enrollment/filtered-language-codes` | Retrieve the list of languages and corresponding ISO 639-1 Codes but only those not already added to Enrollment
 |
| `GET` | `/v3/enrollment/language-codes` | Retrieve the list of languages and corresponding ISO 639-1 Codes
 |
| `GET` | `/v3/enrollment/languages` | Get an array of the language codes that have Enrollment messaging
 |
| `POST` | `/v3/enrollment/languages/delete-multiple` | Delete multiple configured languages from User-Initiated Enrollment settings
 |
| `GET` | `/v3/enrollment/languages/{languageId}` | Retrieve the Enrollment messaging for a language
 |
| `PUT` | `/v3/enrollment/languages/{languageId}` | Edit Enrollment messaging for a language
 |
| `DELETE` | `/v3/enrollment/languages/{languageId}` | Delete the Enrollment messaging for a language
 |

#### enrollment-customization

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/enrollment-customization/parse-markdown` | Parse the given string as markdown text and return Html output
 |
| `GET` | `/v1/enrollment-customization/{id}/all` | Get all Panels for single Enrollment Customization
 |
| `GET` | `/v1/enrollment-customization/{id}/all/{panel-id}` | Get a single Panel for a single Enrollment Customization
 |
| `DELETE` | `/v1/enrollment-customization/{id}/all/{panel-id}` | Delete a single Panel from an Enrollment Customization
 |
| `POST` | `/v1/enrollment-customization/{id}/ldap` | Create an LDAP Panel for a single Enrollment Customization
 |
| `GET` | `/v1/enrollment-customization/{id}/ldap/{panel-id}` | Get a single LDAP panel for a single Enrollment Customization
 |
| `PUT` | `/v1/enrollment-customization/{id}/ldap/{panel-id}` | Update a single LDAP Panel for a single Enrollment Customization
 |
| `DELETE` | `/v1/enrollment-customization/{id}/ldap/{panel-id}` | Delete an LDAP single panel from an Enrollment Customization
 |
| `POST` | `/v1/enrollment-customization/{id}/sso` | Create an SSO Panel for a single Enrollment Customization
 |
| `GET` | `/v1/enrollment-customization/{id}/sso/{panel-id}` | Get a single SSO Panel for a single Enrollment Customization
 |
| `PUT` | `/v1/enrollment-customization/{id}/sso/{panel-id}` | Update a single SSO Panel for a single Enrollment Customization
 |
| `DELETE` | `/v1/enrollment-customization/{id}/sso/{panel-id}` | Delete a single SSO Panel from an Enrollment Customization
 |
| `POST` | `/v1/enrollment-customization/{id}/text` | Create a Text Panel for a single Enrollment Customization
 |
| `GET` | `/v1/enrollment-customization/{id}/text/{panel-id}` | Get a single Text Panel for a single Enrollment Customization
 |
| `PUT` | `/v1/enrollment-customization/{id}/text/{panel-id}` | Update a single Text Panel for a single Enrollment Customization
 |
| `DELETE` | `/v1/enrollment-customization/{id}/text/{panel-id}` | Delete a Text single Panel from an Enrollment Customization
 |
| `GET` | `/v1/enrollment-customization/{id}/text/{panel-id}/markdown` | Get the markdown output of a single Text Panel for a single Enrollment
 |

#### enrollment-customizations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/enrollment-customizations` | Retrieve sorted and paged Enrollment Customizations
 |
| `POST` | `/v2/enrollment-customizations` | Create an Enrollment Customization
 |
| `POST` | `/v2/enrollment-customizations/images` | Upload an image |
| `GET` | `/v2/enrollment-customizations/images/{id}` | Download an enrollment customization image
 |
| `GET` | `/v2/enrollment-customizations/{id}` | Retrieve an Enrollment Customization with the supplied id
 |
| `PUT` | `/v2/enrollment-customizations/{id}` | Update an Enrollment Customization
 |
| `DELETE` | `/v2/enrollment-customizations/{id}` | Delete an Enrollment Customization with the supplied id
 |
| `GET` | `/v2/enrollment-customizations/{id}/history` | Get sorted and paged Enrollment Customization history objects
 |
| `POST` | `/v2/enrollment-customizations/{id}/history` | Add Enrollment Customization history object notes
 |
| `GET` | `/v2/enrollment-customizations/{id}/prestages` | Retrieve the list of Prestages using this Enrollment Customization
 |

#### onboarding

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/onboarding` | Get the current onboarding settings configuration. |
| `PUT` | `/v1/onboarding` | Update the onboarding configuration. |
| `GET` | `/v1/onboarding/eligible-apps` | Retrieves a list of applications that are eligible to be used in an onboarding configuration |
| `GET` | `/v1/onboarding/eligible-configuration-profiles` | Retrieves a list of configuration profiles that are eligible to be used in an onboarding configuration |
| `GET` | `/v1/onboarding/eligible-policies` | Retrieves a list of policies that are eligible to be used in an onboarding configuration |
| `GET` | `/v1/onboarding/history` | Get Onboarding history object
 |
| `POST` | `/v1/onboarding/history` | Add Onboarding history object notes
 |
| `POST` | `/v1/onboarding/history/export` | Export history object collection in specified format for Onboarding
 |

#### reenrollment

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/reenrollment` | Get Re-enrollment object
 |
| `PUT` | `/v1/reenrollment` | Update the Re-enrollment object
 |
| `GET` | `/v1/reenrollment/history` | Get Re-enrollment history object
 |
| `POST` | `/v1/reenrollment/history` | Add specified Re-enrollment history object notes
 |
| `POST` | `/v1/reenrollment/history/export` | Export reenrollment history collection
 |

#### return-to-service

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/return-to-service` | Get all Return to Service Configurations
 |
| `POST` | `/v1/return-to-service` | Create a Return to Service Configuration
 |
| `GET` | `/v1/return-to-service/{id}` | Retrieve a Return to Service Configuration with the supplied id
 |
| `PUT` | `/v1/return-to-service/{id}` | Update a Return to Service Configuration
 |
| `DELETE` | `/v1/return-to-service/{id}` | Delete a Return To Service Configuration with the supplied id
 |

#### service-discovery-enrollment

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/service-discovery-enrollment/well-known-settings` | Get service discovery well-known settings for all organizations |
| `PUT` | `/v1/service-discovery-enrollment/well-known-settings` | Update service discovery well-known settings |

#### supervision-identities

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/supervision-identities` | Search for sorted and paged Supervision Identities
 |
| `POST` | `/v1/supervision-identities` | Create a Supervision Identity for the supplied information
 |
| `POST` | `/v1/supervision-identities/upload` | Upload the Supervision Identity .p12 file
 |
| `GET` | `/v1/supervision-identities/{id}` | Retrieve a Supervision Identity with the supplied id
 |
| `PUT` | `/v1/supervision-identities/{id}` | Update a Supervision Identity with the supplied information
 |
| `DELETE` | `/v1/supervision-identities/{id}` | Delete a Supervision Identity with the supplied id
 |
| `GET` | `/v1/supervision-identities/{id}/download` | Download the Supervision Identity .p12 file
 |

#### v4

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v4/enrollment` | Get Enrollment object and Re-enrollment settings
 |
| `PUT` | `/v4/enrollment` | Update Enrollment object
 |
| `GET` | `/v4/enrollment/access-management` | Get Access Management settings |
| `POST` | `/v4/enrollment/access-management` | Configure Access Management settings
 |

---

## MDM与设备通信

### Jamf Pro API

#### apns-client-push-status

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/apns-client-push-status` | Search for clients with push notifications disabled
 |
| `POST` | `/v1/apns-client-push-status/enable-all-clients` | Enable push notifications for all clients
 |
| `GET` | `/v1/apns-client-push-status/enable-all-clients/status` | Get status of enable all clients request
 |
| `POST` | `/v1/apns-client-push-status/enable-client` | Enable push notifications for a single client
 |

#### check-in

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v3/check-in` | Get Client Check-In settings
 |
| `PUT` | `/v3/check-in` | Update Client Check-In object
 |
| `GET` | `/v3/check-in/history` | Get Client Check-In history object
 |
| `POST` | `/v3/check-in/history` | Add a Note to Client Check-In History
 |

#### deploy-package

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/deploy-package` | Deploy packages using MDM |

#### device-communication-settings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/device-communication-settings` | Retrieves all settings for device communication
 |
| `PUT` | `/v1/device-communication-settings` | Update device communication settings
 |
| `GET` | `/v1/device-communication-settings/history` | Get Device Communication settings history
 |
| `POST` | `/v1/device-communication-settings/history` | Add Device Communication Settings history notes
 |

#### jamf-management-framework

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/jamf-management-framework/redeploy/{id}` | Redeploy Jamf Management Framework
 |

#### mdm

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/mdm/commands` | Get information about mdm commands made by Jamf Pro. |
| `POST` | `/v1/mdm/renew-profile` | Renew MDM Profile
 |
| `POST` | `/v2/mdm/blank-push` | Send blank push notifications to a list of client management IDs. |
| `GET` | `/v2/mdm/commands` | Get information about mdm commands made by Jamf Pro.
 |
| `POST` | `/v2/mdm/commands` | Post a command for creation and queuing
 |

#### mdm-renewal

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `PATCH` | `/v1/mdm-renewal/device-common-details` | Update device common details (partial update)
 |
| `GET` | `/v1/mdm-renewal/device-common-details/{clientManagementId}` | Get device common details for a client management ID
 |
| `GET` | `/v1/mdm-renewal/renewal-strategies/{clientManagementId}` | Get MDM renewal errors and strategies for a client management ID
 |
| `DELETE` | `/v1/mdm-renewal/renewal-strategies/{clientManagementId}` | Delete MDM renewal strategies for a client management ID
 |

---

## 计算机管理

### Jamf Pro API

#### computer-extension-attributes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/computer-extension-attributes` | Retrieve Computer Extension Attributes. |
| `POST` | `/v1/computer-extension-attributes` | Create Computer Extension Attribute. |
| `POST` | `/v1/computer-extension-attributes/delete-multiple` | Delete multiple Computer Extension Attribute at once. |
| `GET` | `/v1/computer-extension-attributes/templates` | Retrieve All Computer Extension Attributes Templates. |
| `GET` | `/v1/computer-extension-attributes/templates/{id}` | Get specified Computer Extension Attribute Template object. |
| `POST` | `/v1/computer-extension-attributes/upload` | Upload Computer Extension Attribute. |
| `GET` | `/v1/computer-extension-attributes/{id}` | Get specified Computer Extension Attribute object. |
| `PUT` | `/v1/computer-extension-attributes/{id}` | Update specified Computer Extension Attribute object. |
| `DELETE` | `/v1/computer-extension-attributes/{id}` | Remove specified Computer Extension Attribute. |
| `GET` | `/v1/computer-extension-attributes/{id}/data-dependency` | Get smart group/advance search dependent objects for a specified computer extension attribute |
| `GET` | `/v1/computer-extension-attributes/{id}/download` | Download the specified Computer Extension Attribute. |
| `GET` | `/v1/computer-extension-attributes/{id}/history` | Get specified Computer Extension Attribute History object |
| `POST` | `/v1/computer-extension-attributes/{id}/history` | Add specified Computer Extension Attribute history object notes |

#### computer-groups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/computer-groups` | Returns the list of all computer groups
 |
| `GET` | `/v2/computer-groups/smart-group-membership/{id}` | Get the membership of a Smart Computer Group
 |
| `GET` | `/v2/computer-groups/smart-groups` | Search for Smart Computer Groups
 |
| `POST` | `/v2/computer-groups/smart-groups` | Create a Smart Computer Group
 |
| `GET` | `/v2/computer-groups/smart-groups/{id}` | Get Smart Computer Group by Id
 |
| `PUT` | `/v2/computer-groups/smart-groups/{id}` | Update a Smart Computer Group
 |
| `DELETE` | `/v2/computer-groups/smart-groups/{id}` | Remove specified Smart Computer Group
 |
| `GET` | `/v2/computer-groups/static-groups` | Search for Static Computer Groups
 |
| `POST` | `/v2/computer-groups/static-groups` | Create membership of a static computer group.
 |
| `GET` | `/v2/computer-groups/static-groups/{id}` | Get Static Computer Group by Id
 |
| `PUT` | `/v2/computer-groups/static-groups/{id}` | Update membership of a static computer group.
 |
| `DELETE` | `/v2/computer-groups/static-groups/{id}` | Remove Static Computer Group by Id
 |

#### computer-inventory

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/computer-inventory/{id}/erase` | Erase a computer
 |
| `POST` | `/v1/computer-inventory/{id}/remove-mdm-profile` | Remove a computer's MDM profile
 |

#### computer-inventory-collection-settings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/computer-inventory-collection-settings` | Returns computer inventory settings |
| `PATCH` | `/v1/computer-inventory-collection-settings` | Update computer inventory settings |
| `POST` | `/v1/computer-inventory-collection-settings/custom-path` | Create Computer Inventory Collection Settings Custom Path |
| `DELETE` | `/v1/computer-inventory-collection-settings/custom-path/{id}` | Delete Custom Path from Computer Inventory Collection Settings |
| `GET` | `/v2/computer-inventory-collection-settings` | Returns computer inventory settings |
| `PATCH` | `/v2/computer-inventory-collection-settings` | Update computer inventory settings |
| `POST` | `/v2/computer-inventory-collection-settings/custom-path` | Create Computer Inventory Collection Settings Custom Path |
| `DELETE` | `/v2/computer-inventory-collection-settings/custom-path/{id}` | Delete Custom Path from Computer Inventory Collection Settings |

#### computer-prestages

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/computer-prestages/scope` | Get all device Scope for all Computer Prestages
 |
| `GET` | `/v2/computer-prestages/{id}/scope` | Get device Scope for a specific Computer Prestage
 |
| `POST` | `/v2/computer-prestages/{id}/scope` | Add device Scope for a specific Computer Prestage
 |
| `PUT` | `/v2/computer-prestages/{id}/scope` | Replace device Scope for a specific Computer Prestage
 |
| `POST` | `/v2/computer-prestages/{id}/scope/delete-multiple` | Remove device Scope for a specific Computer Prestage
 |
| `GET` | `/v3/computer-prestages` | Get sorted and paged Computer Prestages
 |
| `POST` | `/v3/computer-prestages` | Create a Computer Prestage
 |
| `GET` | `/v3/computer-prestages/{id}` | Retrieve a Computer Prestage with the supplied id
 |
| `PUT` | `/v3/computer-prestages/{id}` | Update a Computer Prestage
 |
| `DELETE` | `/v3/computer-prestages/{id}` | Delete a Computer Prestage with the supplied id
 |

#### computercheckin

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computercheckin` | Finds the Jamf Pro computer checkin information |
| `PUT` | `/computercheckin` | Updates the Jamf Pro computer checkin information |

#### computercommands

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computercommands` | Finds all computer commands |
| `POST` | `/computercommands/command/{command}` | Creates a new computer command using command name |
| `POST` | `/computercommands/command/{command}/id/{id}` | Creates a new computer command using command name and device IDs |
| `GET` | `/computercommands/name/{name}` | Finds all computer commands by name |
| `GET` | `/computercommands/uuid/{uuid}` | Finds a computer command by UUID |

#### computerextensionattributes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerextensionattributes` | Finds all computer extension attributes |
| `GET` | `/computerextensionattributes/id/{id}` | Finds computer extension attributes by ID |
| `POST` | `/computerextensionattributes/id/{id}` | Creates a new computer extension attribute by ID |
| `PUT` | `/computerextensionattributes/id/{id}` | Updates an existing computer extension attribute by ID |
| `DELETE` | `/computerextensionattributes/id/{id}` | Deletes a computer extension attribute by ID |
| `GET` | `/computerextensionattributes/name/{name}` | Finds computer extension attributes by name |
| `PUT` | `/computerextensionattributes/name/{name}` | Updates an existing computer extension attribute by name |
| `DELETE` | `/computerextensionattributes/name/{name}` | Deletes a computer extension attribute by name |

#### computergroups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computergroups` | Finds all computer groups |
| `GET` | `/computergroups/id/{id}` | Finds computer groups by ID |
| `POST` | `/computergroups/id/{id}` | Creates a new computer group by ID |
| `PUT` | `/computergroups/id/{id}` | Updates an existing computer group by ID |
| `DELETE` | `/computergroups/id/{id}` | Deletes a computer group by ID |
| `GET` | `/computergroups/name/{name}` | Finds computer groups by name |
| `PUT` | `/computergroups/name/{name}` | Updates an existing computer group by name |
| `DELETE` | `/computergroups/name/{name}` | Deletes a computer group by name |

#### computerhardwaresoftwarereports

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerhardwaresoftwarereports/id/{id}/{start_date}_{end_date}` | Finds hardware/software reports by computer ID |
| `GET` | `/computerhardwaresoftwarereports/id/{id}/{start_date}_{end_date}/subset/{subset}` | Finds a subset of hardware/software reports by computer ID |
| `GET` | `/computerhardwaresoftwarereports/macaddress/{macaddress}/{start_date}_{end_date}` | Finds hardware/software reports by computer MAC address |
| `GET` | `/computerhardwaresoftwarereports/macaddress/{macaddress}/{start_date}_{end_date}/subset/{subset}` | Finds a subset of hardware/software reports by computer MAC address |
| `GET` | `/computerhardwaresoftwarereports/name/{name}/{start_date}_{end_date}` | Finds hardware/software reports by computer name |
| `GET` | `/computerhardwaresoftwarereports/name/{name}/{start_date}_{end_date}/subset/{subset}` | Finds a subset of hardware/software reports by computer name |
| `GET` | `/computerhardwaresoftwarereports/serialnumber/{serialnumber}/{start_date}_{end_date}` | Finds hardware/software reports by computer serial number |
| `GET` | `/computerhardwaresoftwarereports/serialnumber/{serialnumber}/{start_date}_{end_date}/subset/{subset}` | Finds a subset of hardware/software reports by computer serial number |
| `GET` | `/computerhardwaresoftwarereports/udid/{udid}/{start_date}_{end_date}` | Finds hardware/software reports by computer UDID |
| `GET` | `/computerhardwaresoftwarereports/udid/{udid}/{start_date}_{end_date}/subset/{subset}` | Finds a subset of hardware/software reports by computer UDID |

#### computerhistory

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerhistory/id/{id}` | Finds computer history by ID |
| `GET` | `/computerhistory/id/{id}/subset/{subset}` | Finds a subset of computer history data by ID |
| `GET` | `/computerhistory/macaddress/{macaddress}` | Finds computer history by MAC address |
| `GET` | `/computerhistory/macaddress/{macaddress}/subset/{subset}` | Finds a subset of computer history data by MAC address |
| `GET` | `/computerhistory/name/{name}` | Finds computer history by name |
| `GET` | `/computerhistory/name/{name}/subset/{subset}` | Finds a subset of computer history data by name |
| `GET` | `/computerhistory/serialnumber/{serialnumber}` | Finds computer history by serial number |
| `GET` | `/computerhistory/serialnumber/{serialnumber}/subset/{subset}` | Finds a subset of computer history data by serial number |
| `GET` | `/computerhistory/udid/{udid}` | Finds computer history by UDID |
| `GET` | `/computerhistory/udid/{udid}/subset/{subset}` | Finds a subset of computer history data by UDID |

#### computerinventorycollection

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerinventorycollection` | Finds the Jamf Pro computer inventory collection information |
| `PUT` | `/computerinventorycollection` | Updates the Jamf Pro computer inventory collection information |

#### computerinvitations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerinvitations` | Finds all computer invitations |
| `GET` | `/computerinvitations/id/{id}` | Finds computer invitations by id |
| `POST` | `/computerinvitations/id/{id}` | Creates a new computer invitation by id |
| `DELETE` | `/computerinvitations/id/{id}` | Deletes a computer invitation by id |
| `GET` | `/computerinvitations/invitation/{invitation}` | Finds computer invitations by invitation |
| `POST` | `/computerinvitations/invitation/{invitation}` | Creates a new computer invitation by invitation |
| `DELETE` | `/computerinvitations/invitation/{invitation}` | Deletes a computer invitation by invitation |

#### computermanagement

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computermanagement/id/{id}` | Finds computer management information by ID |
| `GET` | `/computermanagement/id/{id}/patchfilter/{filter}` | Display patch management information for a computer and filter |
| `GET` | `/computermanagement/id/{id}/subset/{subset}` | Finds a subset of computer management information by ID |
| `GET` | `/computermanagement/id/{id}/username/{username}` | Finds management information for a computer and username |
| `GET` | `/computermanagement/id/{id}/username/{username}/subset/{subset}` | Finds a subset of management information for a computer and username |
| `GET` | `/computermanagement/macaddress/{macaddress}` | Finds computer management information by MAC address |
| `GET` | `/computermanagement/macaddress/{macaddress}/patchfilter/{filter}` | Display patch management information for a computer and filter |
| `GET` | `/computermanagement/macaddress/{macaddress}/subset/{subset}` | Finds a subset of computer management information by MAC address |
| `GET` | `/computermanagement/macaddress/{macaddress}/username/{username}` | Finds management information for a computer and username |
| `GET` | `/computermanagement/macaddress/{macaddress}/username/{username}/subset/{subset}` | Finds a subset of management information for a computer and username |
| `GET` | `/computermanagement/name/{name}` | Finds computer management information by name |
| `GET` | `/computermanagement/name/{name}/patchfilter/{filter}` | Display patch management information for a computer and filter |
| `GET` | `/computermanagement/name/{name}/subset/{subset}` | Finds a subset of computer management information by name |
| `GET` | `/computermanagement/name/{name}/username/{username}` | Finds management information for a computer and username |
| `GET` | `/computermanagement/name/{name}/username/{username}/subset/{subset}` | Finds a subset of management information for a computer and username |
| `GET` | `/computermanagement/serialnumber/{serialnumber}` | Finds computer management information by serial number |
| `GET` | `/computermanagement/serialnumber/{serialnumber}/patchfilter/{filter}` | Display patch management information for a computer and filter |
| `GET` | `/computermanagement/serialnumber/{serialnumber}/subset/{subset}` | Finds a subset of computer management information by serial number |
| `GET` | `/computermanagement/serialnumber/{serialnumber}/username/{username}` | Finds management information for a computer and username |
| `GET` | `/computermanagement/serialnumber/{serialnumber}/username/{username}/subset/{subset}` | Finds a subset of management information for a computer and username |
| `GET` | `/computermanagement/udid/{udid}` | Finds computer management information by UDID |
| `GET` | `/computermanagement/udid/{udid}/patchfilter/{filter}` | Display patch management information for a computer and filter |
| `GET` | `/computermanagement/udid/{udid}/subset/{subset}` | Finds a subset of computer management information by UDID |
| `GET` | `/computermanagement/udid/{udid}/username/{username}` | Finds management information for a computer and username |
| `GET` | `/computermanagement/udid/{udid}/username/{username}/subset/{subset}` | Finds a subset of management information for a computer and username |

#### computerreports

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerreports` | Finds all computer reports |
| `GET` | `/computerreports/id/{id}` | Finds computer reports by id |
| `GET` | `/computerreports/name/{name}` | Finds computer reports by name |

#### computers

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computers` | Finds all computers |
| `GET` | `/computers/id/{id}` | Finds computers by ID |
| `POST` | `/computers/id/{id}` | Creates a computer |
| `PUT` | `/computers/id/{id}` | Updates an existing computer by ID |
| `DELETE` | `/computers/id/{id}` | Deletes a computer by ID |
| `GET` | `/computers/id/{id}/subset/{subset}` | Finds a subset of information for a computer |
| `GET` | `/computers/macaddress/{macaddress}` | Finds computers by MAC address |
| `PUT` | `/computers/macaddress/{macaddress}` | Updates an existing computer by MAC address |
| `DELETE` | `/computers/macaddress/{macaddress}` | Deletes a computer by MAC address |
| `GET` | `/computers/macaddress/{macaddress}/subset/{subset}` | Finds a subset of data for computers by MAC address |
| `GET` | `/computers/match/name/{matchname}` | Searches for computers that match the provided name parameter |
| `GET` | `/computers/match/{match}` | Searches for computers that match the provided parameter |
| `GET` | `/computers/name/{name}` | Finds the first computer with the given name |
| `PUT` | `/computers/name/{name}` | Updates an existing computer by name |
| `DELETE` | `/computers/name/{name}` | Deletes a computer by name |
| `GET` | `/computers/name/{name}/subset/{subset}` | Finds a subset of data for the first computer with the given name |
| `GET` | `/computers/serialnumber/{serialnumber}` | Finds computers by serial number |
| `PUT` | `/computers/serialnumber/{serialnumber}` | Updates an existing computer by serial number |
| `DELETE` | `/computers/serialnumber/{serialnumber}` | Deletes a computer by serial number |
| `GET` | `/computers/serialnumber/{serialnumber}/subset/{subset}` | Finds a subset of data for computers by serial number |
| `GET` | `/computers/subset/basic` | Finds basic information for all computers |
| `GET` | `/computers/udid/{udid}` | Finds computers by UDID |
| `PUT` | `/computers/udid/{udid}` | Updates an existing computer by UDID |
| `DELETE` | `/computers/udid/{udid}` | Deletes a computer by UDID |
| `GET` | `/computers/udid/{udid}/subset/{subset}` | Finds a subset of data for computers by UDID |
| `POST` | `/v1/computers/{id}/recalculate-smart-groups` | Recalculate a smart group for the given id
 |

#### computers-inventory

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/computers-inventory` | Return paginated Computer Inventory records |
| `POST` | `/v1/computers-inventory` | Create Computer Inventory record |
| `GET` | `/v1/computers-inventory/filevault` | Return paginated FileVault information for all computers |
| `GET` | `/v1/computers-inventory/{id}` | Return General section of a Computer |
| `DELETE` | `/v1/computers-inventory/{id}` | Remove specified Computer record |
| `POST` | `/v1/computers-inventory/{id}/attachments` | Upload attachment and assign to computer |
| `GET` | `/v1/computers-inventory/{id}/attachments/{attachmentId}` | Download attachment file |
| `DELETE` | `/v1/computers-inventory/{id}/attachments/{attachmentId}` | Remove attachment |
| `GET` | `/v1/computers-inventory/{id}/filevault` | Return FileVault information for a specific computer |
| `GET` | `/v1/computers-inventory/{id}/view-device-lock-pin` | Return a computer's Device Lock PIN |
| `GET` | `/v1/computers-inventory/{id}/view-recovery-lock-password` | Return a Computers Recovery Lock Password |
| `GET` | `/v2/computers-inventory` | Return paginated Computer Inventory records |
| `POST` | `/v2/computers-inventory` | Create Computer Inventory record |
| `GET` | `/v2/computers-inventory/filevault` | Return paginated FileVault information for all computers |
| `GET` | `/v2/computers-inventory/{id}` | Return General section of a Computer |
| `DELETE` | `/v2/computers-inventory/{id}` | Remove specified Computer record |
| `POST` | `/v2/computers-inventory/{id}/attachments` | Upload attachment and assign to computer |
| `GET` | `/v2/computers-inventory/{id}/attachments/{attachmentId}` | Download attachment file |
| `DELETE` | `/v2/computers-inventory/{id}/attachments/{attachmentId}` | Remove attachment |
| `GET` | `/v2/computers-inventory/{id}/filevault` | Return FileVault information for a specific computer |
| `GET` | `/v2/computers-inventory/{id}/view-device-lock-pin` | Return a computer's Device Lock PIN |
| `GET` | `/v2/computers-inventory/{id}/view-recovery-lock-password` | Return a Computers Recovery Lock Password |
| `GET` | `/v3/computers-inventory` | Return paginated Computer Inventory records |
| `POST` | `/v3/computers-inventory` | Create Computer Inventory record |
| `GET` | `/v3/computers-inventory/filevault` | Return paginated FileVault information for all computers |
| `GET` | `/v3/computers-inventory/{id}` | Return General section of a Computer |
| `DELETE` | `/v3/computers-inventory/{id}` | Remove specified Computer record |
| `POST` | `/v3/computers-inventory/{id}/attachments` | Upload attachment and assign to computer |
| `GET` | `/v3/computers-inventory/{id}/attachments/{attachmentId}` | Download attachment file |
| `DELETE` | `/v3/computers-inventory/{id}/attachments/{attachmentId}` | Remove attachment |
| `GET` | `/v3/computers-inventory/{id}/filevault` | Return FileVault information for a specific computer |
| `GET` | `/v3/computers-inventory/{id}/view-device-lock-pin` | Return a computer's Device Lock PIN |
| `GET` | `/v3/computers-inventory/{id}/view-recovery-lock-password` | Return a Computers Recovery Lock Password |

#### computers-inventory-detail

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/computers-inventory-detail/{id}` | Return all sections of a computer |
| `PATCH` | `/v1/computers-inventory-detail/{id}` | Update specific fields on a computer |
| `GET` | `/v2/computers-inventory-detail/{id}` | Return all sections of a computer |
| `PATCH` | `/v2/computers-inventory-detail/{id}` | Update specific fields on a computer |
| `GET` | `/v3/computers-inventory-detail/{id}` | Return all sections of a computer |
| `PATCH` | `/v3/computers-inventory-detail/{id}` | Update specific fields on a computer |

#### preview

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/preview/computers` | Return a list of Computers
 |

#### smart-computer-groups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/smart-computer-groups/{id}/recalculate` | Recalculate the smart group for the given id
 |

---

## 移动设备管理

### Jamf Pro API

#### devices

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/devices/extensionAttributes` | Get Mobile Device Extension Attribute values placed in select paramter
 |

#### mobile-device-enrollment-profile

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/mobile-device-enrollment-profile/{id}/download-profile` | Retrieve the MDM Enrollment Profile
 |

#### mobile-device-extension-attributes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/mobile-device-extension-attributes` | Retrieve Mobile Device Extension Attributes. |
| `POST` | `/v1/mobile-device-extension-attributes` | Create Mobile Device Extension Attribute. |
| `GET` | `/v1/mobile-device-extension-attributes/{id}` | Get specified Mobile Device Extension Attribute object. |
| `PUT` | `/v1/mobile-device-extension-attributes/{id}` | Update specified Mobile Device Extension Attribute object. |
| `DELETE` | `/v1/mobile-device-extension-attributes/{id}` | Delete a Mobile Device Extension Attribute by ID. |
| `GET` | `/v1/mobile-device-extension-attributes/{id}/data-dependency` | Get smart group dependent object for a specified mobile device extension attribute |
| `GET` | `/v1/mobile-device-extension-attributes/{id}/history` | Get specified Mobile Device Extension Attribute History object |
| `POST` | `/v1/mobile-device-extension-attributes/{id}/history` | Add specified Mobile Device Extension Attribute history object notes |

#### mobile-device-groups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/mobile-device-groups` | Return the list of all Mobile Device Groups
 |
| `GET` | `/v1/mobile-device-groups/smart-group-membership/{id}` | Get Smart Group Membership by Id
 |
| `GET` | `/v1/mobile-device-groups/smart-groups` | Get Smart Groups
 |
| `POST` | `/v1/mobile-device-groups/smart-groups` | Create a smart group
 |
| `GET` | `/v1/mobile-device-groups/smart-groups/{id}` | Get Smart Group by Id
 |
| `PUT` | `/v1/mobile-device-groups/smart-groups/{id}` | Update a smart group
 |
| `DELETE` | `/v1/mobile-device-groups/smart-groups/{id}` | Remove Smart Group by Id
 |
| `GET` | `/v1/mobile-device-groups/static-group-membership/{id}` | Get Static Group Membership by Id
 |
| `GET` | `/v1/mobile-device-groups/static-groups` | Get Static Groups
 |
| `POST` | `/v1/mobile-device-groups/static-groups` | Create membership of a static group
 |
| `GET` | `/v1/mobile-device-groups/static-groups/{id}` | Get Static Group by Id
 |
| `PATCH` | `/v1/mobile-device-groups/static-groups/{id}` | Update membership of a static group
 |
| `POST` | `/v1/mobile-device-groups/{id}/erase` | Erase all devices in the group
 |

#### mobile-device-prestages

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/mobile-device-prestages` | Get sorted and paged Mobile Device Prestages
 |
| `POST` | `/v2/mobile-device-prestages` | Create a Mobile Device Prestage
 |
| `GET` | `/v2/mobile-device-prestages/scope` | Get all Device Scope for all Mobile Device Prestages
 |
| `GET` | `/v2/mobile-device-prestages/syncs` | Get all Prestage sync States for all prestages
 |
| `GET` | `/v2/mobile-device-prestages/{id}` | Retrieve a Mobile Device Prestage with the supplied id
 |
| `PUT` | `/v2/mobile-device-prestages/{id}` | Update a Mobile Device Prestage
 |
| `DELETE` | `/v2/mobile-device-prestages/{id}` | Delete a Mobile Device Prestage with the supplied id
 |
| `GET` | `/v2/mobile-device-prestages/{id}/attachments` | Get attachments for a Mobile Device Prestage
 |
| `POST` | `/v2/mobile-device-prestages/{id}/attachments` | Add an attachment to a Mobile Device Prestage
 |
| `POST` | `/v2/mobile-device-prestages/{id}/attachments/delete-multiple` | Remove an attachment for a Mobile Device Prestage
 |
| `GET` | `/v2/mobile-device-prestages/{id}/history` | Get sorted and paged Mobile Device Prestage history objects
 |
| `POST` | `/v2/mobile-device-prestages/{id}/history` | Add Mobile Device Prestage history object notes
 |
| `GET` | `/v2/mobile-device-prestages/{id}/scope` | Get Device Scope for a specific Mobile Device Prestage
 |
| `POST` | `/v2/mobile-device-prestages/{id}/scope` | Add Device Scope for a specific Mobile Device Prestage
 |
| `PUT` | `/v2/mobile-device-prestages/{id}/scope` | Replace Device Scope for a specific Mobile Device Prestage
 |
| `POST` | `/v2/mobile-device-prestages/{id}/scope/delete-multiple` | Remove Device Scope for a specific Mobile Device Prestage
 |
| `GET` | `/v2/mobile-device-prestages/{id}/syncs` | Get all prestage sync states for a single prestage
 |
| `GET` | `/v2/mobile-device-prestages/{id}/syncs/latest` | Get the latest Sync State for a single Prestage
 |
| `GET` | `/v3/mobile-device-prestages` | Get sorted and paged Mobile Device Prestages
 |
| `POST` | `/v3/mobile-device-prestages` | Create a Mobile Device Prestage
 |
| `GET` | `/v3/mobile-device-prestages/{id}` | Retrieve a Mobile Device Prestage with the supplied id
 |
| `PUT` | `/v3/mobile-device-prestages/{id}` | Update a Mobile Device Prestage
 |
| `DELETE` | `/v3/mobile-device-prestages/{id}` | Delete a Mobile Device Prestage with the supplied id
 |
| `GET` | `/v3/mobile-device-prestages/{id}/attachments` | Get attachments for a Mobile Device Prestage
 |
| `POST` | `/v3/mobile-device-prestages/{id}/attachments` | Add an attachment to a Mobile Device Prestage
 |
| `POST` | `/v3/mobile-device-prestages/{id}/attachments/delete-multiple` | Remove an attachment for a Mobile Device Prestage
 |
| `GET` | `/v3/mobile-device-prestages/{id}/history` | Get sorted and paged Mobile Device Prestage history objects
 |
| `POST` | `/v3/mobile-device-prestages/{id}/history` | Add Mobile Device Prestage history object notes
 |

#### mobile-devices

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/mobile-devices/{id}/recalculate-smart-groups` | Recalculate all smart groups for the given device id and then return count of smart groups that device fall into
 |
| `GET` | `/v2/mobile-devices` | Get Mobile Device objects
 |
| `GET` | `/v2/mobile-devices/detail` | Return paginated Mobile Device Inventory records |
| `GET` | `/v2/mobile-devices/{id}` | Get Mobile Device
 |
| `PATCH` | `/v2/mobile-devices/{id}` | Update fields on a mobile device that are allowed to be modified by users
 |
| `GET` | `/v2/mobile-devices/{id}/detail` | Get Mobile Device
 |
| `POST` | `/v2/mobile-devices/{id}/erase` | Erase a Mobile Device
 |
| `GET` | `/v2/mobile-devices/{id}/paired-devices` | Return paginated Mobile Device Inventory records of all paired devices for the device
 |
| `POST` | `/v2/mobile-devices/{id}/unmanage` | Unmanage a Mobile Device
 |

#### mobiledevicecommands

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledevicecommands` | Finds all mobile device commands |
| `POST` | `/mobiledevicecommands/command` | Creates a new mobile device command |
| `GET` | `/mobiledevicecommands/command/{command}` | Finds all mobile device commands for specified command |
| `POST` | `/mobiledevicecommands/command/{command}/id/{id_list}` | Creates a new mobile device command |
| `GET` | `/mobiledevicecommands/name/{name}` | Finds all mobile device commands by command name |
| `GET` | `/mobiledevicecommands/uuid/{uuid}` | Finds a mobile device command by UUID |

#### mobiledeviceconfigurationprofiles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledeviceconfigurationprofiles` | Finds all mobile device configuration profiles |
| `GET` | `/mobiledeviceconfigurationprofiles/id/{id}` | Finds mobile device configuration profiles by ID |
| `POST` | `/mobiledeviceconfigurationprofiles/id/{id}` | Creates a new mobile device configuration profile by ID |
| `PUT` | `/mobiledeviceconfigurationprofiles/id/{id}` | Updates an existing mobile device configuration profile by ID |
| `DELETE` | `/mobiledeviceconfigurationprofiles/id/{id}` | Deletes a mobile device configuration profile by ID |
| `GET` | `/mobiledeviceconfigurationprofiles/id/{id}/subset/{subset}` | Finds a subset of data for a mobile device configuration profile by ID |
| `GET` | `/mobiledeviceconfigurationprofiles/name/{name}` | Finds mobile device configuration profiles by name |
| `PUT` | `/mobiledeviceconfigurationprofiles/name/{name}` | Updates an existing mobile device configuration profile by name |
| `DELETE` | `/mobiledeviceconfigurationprofiles/name/{name}` | Deletes a mobile device configuration profile by name |
| `GET` | `/mobiledeviceconfigurationprofiles/name/{name}/subset/{subset}` | Finds a subset of data for mobile device configuration profiles by name |

#### mobiledeviceenrollmentprofiles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledeviceenrollmentprofiles` | Finds all mobile device enrollment profiles |
| `GET` | `/mobiledeviceenrollmentprofiles/id/{id}` | Finds mobile device enrollment profiles by ID |
| `POST` | `/mobiledeviceenrollmentprofiles/id/{id}` | Creates a new mobile device enrollment profile by ID |
| `PUT` | `/mobiledeviceenrollmentprofiles/id/{id}` | Updates an existing mobile device enrollment profile by ID |
| `DELETE` | `/mobiledeviceenrollmentprofiles/id/{id}` | Deletes a mobile device enrollment profile by ID |
| `GET` | `/mobiledeviceenrollmentprofiles/id/{id}/subset/{subset}` | Finds a subset of data for an enrollment profile |
| `GET` | `/mobiledeviceenrollmentprofiles/invitation/{invitation}` | Finds mobile device enrollment profiles by invitation |
| `PUT` | `/mobiledeviceenrollmentprofiles/invitation/{invitation}` | Updates an existing mobile device enrollment profile by invitation |
| `DELETE` | `/mobiledeviceenrollmentprofiles/invitation/{invitation}` | Deletes a mobile device enrollment profile by invitation |
| `GET` | `/mobiledeviceenrollmentprofiles/name/{name}` | Finds mobile device enrollment profiles by name |
| `PUT` | `/mobiledeviceenrollmentprofiles/name/{name}` | Updates an existing mobile device enrollment profile by name |
| `DELETE` | `/mobiledeviceenrollmentprofiles/name/{name}` | Deletes a mobile device enrollment profile by name |
| `GET` | `/mobiledeviceenrollmentprofiles/name/{name}/subset/{subset}` | Finds a subset of data for mobile device enrollment profiles by name |

#### mobiledeviceextensionattributes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledeviceextensionattributes` | Finds all mobile device extension attributes |
| `GET` | `/mobiledeviceextensionattributes/id/{id}` | Finds mobile device extension attributes by ID |
| `POST` | `/mobiledeviceextensionattributes/id/{id}` | Creates a new mobile device extension attribute by ID |
| `PUT` | `/mobiledeviceextensionattributes/id/{id}` | Updates an existing mobile device extension attribute by ID |
| `DELETE` | `/mobiledeviceextensionattributes/id/{id}` | Deletes a mobile device extension attribute by ID |
| `GET` | `/mobiledeviceextensionattributes/name/{name}` | Finds mobiledeviceextensionattributes by name |
| `PUT` | `/mobiledeviceextensionattributes/name/{name}` | Updates an existing mobile device extension attribute by name |
| `DELETE` | `/mobiledeviceextensionattributes/name/{name}` | Deletes a mobile device extension attribute by name |

#### mobiledevicegroups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledevicegroups` | Finds all mobile device groups |
| `GET` | `/mobiledevicegroups/id/{id}` | Finds mobile device groups by ID |
| `POST` | `/mobiledevicegroups/id/{id}` | Creates a new mobile device group by ID |
| `PUT` | `/mobiledevicegroups/id/{id}` | Updates an existing mobile device group by ID |
| `DELETE` | `/mobiledevicegroups/id/{id}` | Deletes a mobile device group by ID |
| `GET` | `/mobiledevicegroups/name/{name}` | Finds mobile device groups by name |
| `PUT` | `/mobiledevicegroups/name/{name}` | Updates an existing mobile device group by name |
| `DELETE` | `/mobiledevicegroups/name/{name}` | Deletes a mobile device group by name |

#### mobiledevicehistory

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledevicehistory/id/{id}` | Finds mobile device history by ID |
| `GET` | `/mobiledevicehistory/id/{id}/subset/{subset}` | finds a subset of data for a mobile device history |
| `GET` | `/mobiledevicehistory/macaddress/{macaddress}` | Finds mobile device history by wifi mac address |
| `GET` | `/mobiledevicehistory/macaddress/{macaddress}/subset/{subset}` | Finds a subset of data for mobile device history by wifi mac address |
| `GET` | `/mobiledevicehistory/name/{name}` | Finds mobile device history by name |
| `GET` | `/mobiledevicehistory/name/{name}/subset/{subset}` | Finds a subset of data for mobile device history by name |
| `GET` | `/mobiledevicehistory/serialnumber/{serialnumber}` | Finds mobile device history by serial number |
| `GET` | `/mobiledevicehistory/serialnumber/{serialnumber}/subset/{subset}` | Finds a subset of data for mobile device history by serial number |
| `GET` | `/mobiledevicehistory/udid/{udid}` | Finds mobile device history by UDID |
| `GET` | `/mobiledevicehistory/udid/{udid}/subset/{subset}` | Finds a subset of data for mobile device history by UDID |

#### mobiledeviceinvitations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledeviceinvitations` | Finds all mobile device invitations |
| `GET` | `/mobiledeviceinvitations/id/{id}` | Finds mobile device invitations by id |
| `POST` | `/mobiledeviceinvitations/id/{id}` | Creates a new mobile device invitation by id |
| `DELETE` | `/mobiledeviceinvitations/id/{id}` | Deletes a mobile device invitation by id |
| `GET` | `/mobiledeviceinvitations/invitation/{invitation}` | Finds mobile device invitations by invitation |
| `POST` | `/mobiledeviceinvitations/invitation/{invitation}` | Creates a new mobile device invitation by invitation |
| `DELETE` | `/mobiledeviceinvitations/invitation/{invitation}` | Deletes a mobile device invitation by invitation |

#### mobiledeviceprovisioningprofiles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledeviceprovisioningprofiles` | Finds all mobile device provisioning profiles |
| `GET` | `/mobiledeviceprovisioningprofiles/id/{id}` | Finds a mobile device provisioning profiles by id |
| `POST` | `/mobiledeviceprovisioningprofiles/id/{id}` | Creates a mobile device provisioning profiles by id |
| `PUT` | `/mobiledeviceprovisioningprofiles/id/{id}` | Updates an existing mobile device provisioning profiles by id |
| `DELETE` | `/mobiledeviceprovisioningprofiles/id/{id}` | Deletes a mobile device provisioning profiles by id |
| `GET` | `/mobiledeviceprovisioningprofiles/name/{name}` | Finds a mobile device provisioning profiles by name |
| `POST` | `/mobiledeviceprovisioningprofiles/name/{name}` | Creates a mobile device provisioning profiles by name |
| `PUT` | `/mobiledeviceprovisioningprofiles/name/{name}` | Updates an existing mobile device provisioning profiles by name |
| `DELETE` | `/mobiledeviceprovisioningprofiles/name/{name}` | Deletes a mobile device provisioning profiles by name |
| `GET` | `/mobiledeviceprovisioningprofiles/uuid/{uuid}` | Finds a mobile device provisioning profiles by uuid |
| `POST` | `/mobiledeviceprovisioningprofiles/uuid/{uuid}` | Creates a mobile device provisioning profiles by uuid |
| `PUT` | `/mobiledeviceprovisioningprofiles/uuid/{uuid}` | Updates an existing mobile device provisioning profiles by uuid |
| `DELETE` | `/mobiledeviceprovisioningprofiles/uuid/{uuid}` | Deletes a mobile device provisioning profiles by uuid |

#### mobiledevices

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledevices` | Finds all mobile devices |
| `GET` | `/mobiledevices/id/{id}` | Finds mobile devices by ID |
| `POST` | `/mobiledevices/id/{id}` | Creates a new mobile device by ID |
| `PUT` | `/mobiledevices/id/{id}` | Updates an existing mobile device by ID |
| `DELETE` | `/mobiledevices/id/{id}` | Deletes a mobile device by ID |
| `GET` | `/mobiledevices/id/{id}/subset/{subset}` | Finds a subset of data for a mobile device |
| `GET` | `/mobiledevices/macaddress/{macaddress}` | Finds mobile devices by Mac address |
| `PUT` | `/mobiledevices/macaddress/{macaddress}` | Updates an existing mobile device by Mac address |
| `DELETE` | `/mobiledevices/macaddress/{macaddress}` | Deletes a mobile device by Mac address |
| `GET` | `/mobiledevices/macaddress/{macaddress}/subset/{subset}` | Finds a subset of data for mobile devices by Mac address |
| `GET` | `/mobiledevices/match/{match}` | Searches for mobile devices that match the provided parameter |
| `GET` | `/mobiledevices/name/{name}` | Finds mobile devices by name |
| `PUT` | `/mobiledevices/name/{name}` | Updates an existing mobile device by name |
| `DELETE` | `/mobiledevices/name/{name}` | Deletes a mobile device by name |
| `GET` | `/mobiledevices/name/{name}/subset/{subset}` | Finds a subset of data for mobile devices by name |
| `GET` | `/mobiledevices/serialnumber/{serialnumber}` | Finds mobile devices by serial number |
| `PUT` | `/mobiledevices/serialnumber/{serialnumber}` | Updates an existing mobile device by serial number |
| `DELETE` | `/mobiledevices/serialnumber/{serialnumber}` | Deletes a mobile device by serial number |
| `GET` | `/mobiledevices/serialnumber/{serialnumber}/subset/{subset}` | Finds a subset of data for mobile devices by serial number |
| `GET` | `/mobiledevices/udid/{udid}` | Finds mobile devices by UDID |
| `PUT` | `/mobiledevices/udid/{udid}` | Updates an existing mobile device by UDID |
| `DELETE` | `/mobiledevices/udid/{udid}` | Deletes a mobile device by UDID |
| `GET` | `/mobiledevices/udid/{udid}/subset/{subset}` | Finds a subset of data for mobile devices by UDID |

#### smart-mobile-device-groups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/smart-mobile-device-groups/{id}/recalculate` | Recalculate a smart group for the given id then return the ids for the devices in the smart group
 |

---

## 应用与软件管理

### Jamf Pro API

#### app-request

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/app-request/form-input-fields` | Search for Form Input Fields
 |
| `POST` | `/v1/app-request/form-input-fields` | Create Form Input Field record
 |
| `PUT` | `/v1/app-request/form-input-fields` | Replace all Form Input Fields
 |
| `GET` | `/v1/app-request/form-input-fields/{id}` | Get specified Form Input Field object
 |
| `PUT` | `/v1/app-request/form-input-fields/{id}` | Update specified Form Input Field object
 |
| `DELETE` | `/v1/app-request/form-input-fields/{id}` | Remove specified Form Input Field record
 |
| `GET` | `/v1/app-request/settings` | Get Applicastion Request Settings
 |
| `PUT` | `/v1/app-request/settings` | Update Application Request Settings
 |

#### app-store-country-codes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/app-store-country-codes` | Return a list of Countries and the associated Codes
 |

#### computerapplications

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerapplications/application/{application}` | Finds computer applications by name |
| `GET` | `/computerapplications/application/{application}/inventory/{inventory}` | Finds computer applications by name with additional display fields |
| `GET` | `/computerapplications/application/{application}/version/{version}` | Finds computer applications by name and version |
| `GET` | `/computerapplications/application/{application}/version/{version}/inventory/{inventory}` | Finds computer applications by name and version |

#### computerapplicationusage

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/computerapplicationusage/id/{id}/{start_date}_{end_date}` | Finds computer application usage by computer ID |
| `GET` | `/computerapplicationusage/macaddress/{macaddress}/{start_date}_{end_date}` | Finds computer application usage by computer MAC address |
| `GET` | `/computerapplicationusage/name/{name}/{start_date}_{end_date}` | Finds computer application usage by computer name |
| `GET` | `/computerapplicationusage/serialnumber/{serialnumber}/{start_date}_{end_date}` | Finds computer application usage by computer serial number |
| `GET` | `/computerapplicationusage/udid/{udid}/{start_date}_{end_date}` | Finds computer application usage by computer UDID |

#### licensedsoftware

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/licensedsoftware` | Finds all licensed software |
| `GET` | `/licensedsoftware/id/{id}` | Finds licensed software by ID |
| `POST` | `/licensedsoftware/id/{id}` | Creates new licensed software by ID |
| `PUT` | `/licensedsoftware/id/{id}` | Updates existing licensed software by ID |
| `DELETE` | `/licensedsoftware/id/{id}` | Deletes licensed software by ID |
| `GET` | `/licensedsoftware/name/{name}` | Finds licensed software by name |
| `PUT` | `/licensedsoftware/name/{name}` | Updates an existing licensed software by name |
| `DELETE` | `/licensedsoftware/name/{name}` | Deletes licensed software by name |

#### macapplications

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/macapplications` | Finds all mac applications |
| `GET` | `/macapplications/id/{id}` | Finds mac applications by ID |
| `POST` | `/macapplications/id/{id}` | Creates a new mac application by ID |
| `PUT` | `/macapplications/id/{id}` | Updates an existing mac application by ID |
| `DELETE` | `/macapplications/id/{id}` | Deletes a mac application by ID |
| `GET` | `/macapplications/id/{id}/subset/{subset}` | Finds a subset of date for a mac application by ID |
| `GET` | `/macapplications/name/{name}` | Finds mac applications by name |
| `PUT` | `/macapplications/name/{name}` | Updates an existing mac application by name |
| `DELETE` | `/macapplications/name/{name}` | Deletes a mac application by name |
| `GET` | `/macapplications/name/{name}/subset/{subset}` | Finds a subset of data for mac applications by name |

#### macos-managed-software-updates

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/macos-managed-software-updates/available-updates` | Retrieve available MacOs Managed Software Updates |
| `POST` | `/v1/macos-managed-software-updates/send-updates` | Send MacOs Managed Software Updates |

#### managed-software-updates

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/managed-software-updates/available-updates` | Retrieve available macOS and iOS Managed Software Updates |
| `GET` | `/v1/managed-software-updates/plans` | Retrieve Managed Software Update Plans |
| `POST` | `/v1/managed-software-updates/plans` | Create a Managed Software Update Plan |
| `GET` | `/v1/managed-software-updates/plans/feature-toggle` | Retrieve current value of the Feature Toggle |
| `PUT` | `/v1/managed-software-updates/plans/feature-toggle` | Updates Feature Toggle Value |
| `POST` | `/v1/managed-software-updates/plans/feature-toggle/abandon` | Force stops any ongoing or stalled feature-toggle processes |
| `GET` | `/v1/managed-software-updates/plans/feature-toggle/status` | Retrieves background status of the Feature Toggle |
| `POST` | `/v1/managed-software-updates/plans/group` | Create Managed Software Update Plans for a Group |
| `GET` | `/v1/managed-software-updates/plans/group/{id}` | Retrieve Managed Software Update Plans for a Group |
| `GET` | `/v1/managed-software-updates/plans/{id}` | Retrieve a Managed Software Update Plan |
| `GET` | `/v1/managed-software-updates/plans/{id}/declarations` | Retrieve all Declarations associated with a Managed Software Update Plan |
| `GET` | `/v1/managed-software-updates/plans/{id}/events` | Retrieve a Managed Software Update Plan Event Store |
| `GET` | `/v1/managed-software-updates/update-statuses` | Retrieve Managed Software Update Statuses |
| `GET` | `/v1/managed-software-updates/update-statuses/computer-groups/{id}` | Retrieve Managed Software Update Statuses for Computer Groups |
| `GET` | `/v1/managed-software-updates/update-statuses/computers/{id}` | Retrieve Managed Software Update Statuses for Computers |
| `GET` | `/v1/managed-software-updates/update-statuses/mobile-devices/{id}` | Retrieve Managed Software Update Statuses for Mobile Devices |

#### mobile-device-apps

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/mobile-device-apps/reinstall-app-config` | Reinstall App Config for Managed iOS Apps
 |

#### mobiledeviceapplications

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/mobiledeviceapplications` | Finds all mobile device applications |
| `GET` | `/mobiledeviceapplications/bundleid/{bundleid}` | Finds mobile device applications by bundle ID |
| `PUT` | `/mobiledeviceapplications/bundleid/{bundleid}` | Updates an existing mobile device application by bundle ID |
| `DELETE` | `/mobiledeviceapplications/bundleid/{bundleid}` | Deletes a mobile device application by bundle ID |
| `GET` | `/mobiledeviceapplications/bundleid/{bundleid}/version/{version}` | Finds mobile device applications by bundle ID and version |
| `PUT` | `/mobiledeviceapplications/bundleid/{bundleid}/version/{version}` | Updates an existing mobile device application by bundle ID and version |
| `DELETE` | `/mobiledeviceapplications/bundleid/{bundleid}/version/{version}` | Deletes a mobile device application by bundle ID and version |
| `GET` | `/mobiledeviceapplications/id/{id}` | Finds mobile device applications by ID |
| `POST` | `/mobiledeviceapplications/id/{id}` | Creates a new mobile device application by ID |
| `PUT` | `/mobiledeviceapplications/id/{id}` | Updates an existing mobile device application by ID |
| `DELETE` | `/mobiledeviceapplications/id/{id}` | Deletes a mobile device application by ID |
| `GET` | `/mobiledeviceapplications/id/{id}/subset/{subset}` | Finds a subset of data for a mobile device application by ID |
| `GET` | `/mobiledeviceapplications/name/{name}` | Finds mobile device applications by name |
| `PUT` | `/mobiledeviceapplications/name/{name}` | Updates an existing mobile device application by name |
| `DELETE` | `/mobiledeviceapplications/name/{name}` | Deletes a mobile device application by name |
| `GET` | `/mobiledeviceapplications/name/{name}/subset/{subset}` | Finds a subset of data for mobile device applications by name |

#### restrictedsoftware

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/restrictedsoftware` | Finds all restricted software |
| `GET` | `/restrictedsoftware/id/{id}` | Finds restricted software by ID |
| `POST` | `/restrictedsoftware/id/{id}` | Creates a new restricted software by ID |
| `PUT` | `/restrictedsoftware/id/{id}` | Updates an existing restricted software by ID |
| `DELETE` | `/restrictedsoftware/id/{id}` | Deletes a restricted software by ID |
| `GET` | `/restrictedsoftware/name/{name}` | Finds restricted software by name |
| `PUT` | `/restrictedsoftware/name/{name}` | Updates an existing restricted software by name |
| `DELETE` | `/restrictedsoftware/name/{name}` | Deletes a restricted software by name |

#### volume-purchasing-locations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/volume-purchasing-locations` | Retrieve Volume Purchasing Locations |
| `POST` | `/v1/volume-purchasing-locations` | Create a Volume Purchasing Location |
| `GET` | `/v1/volume-purchasing-locations/{id}` | Retrieve a Volume Purchasing Location with the supplied id |
| `PATCH` | `/v1/volume-purchasing-locations/{id}` | Update a Volume Purchasing Location |
| `DELETE` | `/v1/volume-purchasing-locations/{id}` | Delete a Volume Purchasing Location with the supplied id |
| `GET` | `/v1/volume-purchasing-locations/{id}/content` | Retrieve the Volume Purchasing Content for the Volume Purchasing Location with the supplied id |
| `GET` | `/v1/volume-purchasing-locations/{id}/history` | Get specified Volume Purchasing Location history object
 |
| `POST` | `/v1/volume-purchasing-locations/{id}/history` | Add specified Volume Purchasing Location history object notes
 |
| `POST` | `/v1/volume-purchasing-locations/{id}/reclaim` | Reclaim a Volume Purchasing Location with the supplied id |
| `POST` | `/v1/volume-purchasing-locations/{id}/revoke-licenses` | Revoke licenses for a Volume Purchasing Location with the supplied id |

#### volume-purchasing-subscriptions

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/volume-purchasing-subscriptions` | Retrieve Volume Purchasing Subscriptions |
| `POST` | `/v1/volume-purchasing-subscriptions` | Create a Volume Purchasing Subscription |
| `GET` | `/v1/volume-purchasing-subscriptions/{id}` | Retrieve a Volume Purchasing Subscription with the supplied id |
| `PUT` | `/v1/volume-purchasing-subscriptions/{id}` | Update a Volume Purchasing Subscription |
| `DELETE` | `/v1/volume-purchasing-subscriptions/{id}` | Delete a Volume Purchasing Subscription with the supplied id |
| `GET` | `/v1/volume-purchasing-subscriptions/{id}/history` | Get specified Volume Purchasing Subscription history object
 |
| `POST` | `/v1/volume-purchasing-subscriptions/{id}/history` | Add Volume Purchasing Subscription history object notes
 |

---

## 配置文件与策略

### Jamf Pro API

#### byoprofiles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/byoprofiles` | Finds all personal device profiles |
| `GET` | `/byoprofiles/id/{id}` | Finds personal device profile by ID |
| `POST` | `/byoprofiles/id/{id}` | Creates a personal device profile by ID |
| `PUT` | `/byoprofiles/id/{id}` | Updates a personal device profile by ID |
| `DELETE` | `/byoprofiles/id/{id}` | Deletes a personal device profile by ID |
| `GET` | `/byoprofiles/name/{name}` | Finds a personal device profile by name |
| `PUT` | `/byoprofiles/name/{name}` | Updates a personal device profile by name |
| `DELETE` | `/byoprofiles/name/{name}` | Deletes a personal device profile by name |

#### ddm

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/ddm/{clientManagementId}/status-items` | Retrieve the Status Items from the latest Status Report for a device |
| `GET` | `/v1/ddm/{clientManagementId}/status-items/{key}` | Retrieve a Status Item from the latest Status Report for a device |
| `POST` | `/v1/ddm/{clientManagementId}/sync` | Force a device DDM sync |

#### dss-declarations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/dss-declarations/{declarationId}` | Retrieve an existing declaration |

#### osxconfigurationprofiles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/osxconfigurationprofiles` | Finds all OS X configuration profiles |
| `GET` | `/osxconfigurationprofiles/id/{id}` | Finds OS X configuration profiles by ID |
| `POST` | `/osxconfigurationprofiles/id/{id}` | Creates a new OS X configuration profile by ID |
| `PUT` | `/osxconfigurationprofiles/id/{id}` | Updates an existing OS X configuration profile by ID |
| `DELETE` | `/osxconfigurationprofiles/id/{id}` | Deletes a OS X configuration profile by ID |
| `GET` | `/osxconfigurationprofiles/id/{id}/subset/{subset}` | Finds a subset of data for an OS X configuration profile |
| `GET` | `/osxconfigurationprofiles/name/{name}` | Finds OS X configuration profiles by name |
| `PUT` | `/osxconfigurationprofiles/name/{name}` | Updates an existing OS X configuration profile by name |
| `DELETE` | `/osxconfigurationprofiles/name/{name}` | Deletes a OS X configuration profile by name |
| `GET` | `/osxconfigurationprofiles/name/{name}/subset/{subset}` | Finds a subset of data for OS X configuration profiles by name |

#### policies

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/policies` | Finds all policies |
| `GET` | `/policies/category/{category}` | Finds all policies by category |
| `GET` | `/policies/createdBy/{createdBy}` | Finds all policies by type |
| `GET` | `/policies/id/{id}` | Finds policies by ID |
| `POST` | `/policies/id/{id}` | Creates a new policy by ID |
| `PUT` | `/policies/id/{id}` | Updates an existing policy by ID |
| `DELETE` | `/policies/id/{id}` | Deletes a policy by ID |
| `GET` | `/policies/id/{id}/subset/{subset}` | Finds a subset of data for a policy |
| `GET` | `/policies/name/{name}` | Finds policies by name |
| `PUT` | `/policies/name/{name}` | Updates an existing policy by name |
| `DELETE` | `/policies/name/{name}` | Deletes a policy by name |
| `GET` | `/policies/name/{name}/subset/{subset}` | Finds a subset of data for policies by name |

#### policy-properties

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/policy-properties` | Get Policy Properties object
 |
| `PUT` | `/v1/policy-properties` | Update Policy Properties object
 |

#### settings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/settings/obj/policyProperties` | Get Policy Properties object
 |
| `PUT` | `/settings/obj/policyProperties` | Update Policy Properties object
 |

---

## 补丁管理

### Jamf Pro API

#### patch-management-accept-disclaimer

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v2/patch-management-accept-disclaimer` | Accept Patch Management disclaimer
 |

#### patch-policies

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/patch-policies` | Retrieve Patch Policies |
| `GET` | `/v2/patch-policies/policy-details` | Retrieve Patch Policies |
| `GET` | `/v2/patch-policies/{id}/dashboard` | Return whether or not the requested patch policy is on the dashboard
 |
| `POST` | `/v2/patch-policies/{id}/dashboard` | Add a patch policy to the dashboard
 |
| `DELETE` | `/v2/patch-policies/{id}/dashboard` | Remove a patch policy from the dashboard
 |
| `GET` | `/v2/patch-policies/{id}/logs` | Retrieve Patch Policy Logs
 |
| `GET` | `/v2/patch-policies/{id}/logs/eligible-retry-count` | Return the count of the Patch Policy Logs for the patch policy id that are eligible for a retry attempt
 |
| `POST` | `/v2/patch-policies/{id}/logs/retry` | Send retry attempts for specific devices |
| `POST` | `/v2/patch-policies/{id}/logs/retry-all` | Send retry attempts for all devices |
| `GET` | `/v2/patch-policies/{id}/logs/{deviceId}` | Retrieves a single Patch Policy Log
 |
| `GET` | `/v2/patch-policies/{id}/logs/{deviceId}/details` | Return attempt details for a specific log |

#### patch-software-title-configurations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/patch-software-title-configurations` | Retrieve Patch Software Title Configurations |
| `POST` | `/v2/patch-software-title-configurations` | Create Patch Software Title Configurations |
| `GET` | `/v2/patch-software-title-configurations/{id}` | Retrieve Patch Software Title Configurations with the supplied id |
| `PATCH` | `/v2/patch-software-title-configurations/{id}` | Update Patch Software Title Configurations |
| `DELETE` | `/v2/patch-software-title-configurations/{id}` | Delete Patch Software Title Configurations with the supplied id |
| `GET` | `/v2/patch-software-title-configurations/{id}/dashboard` | Return whether or not the requested software title configuration is on the dashboard
 |
| `POST` | `/v2/patch-software-title-configurations/{id}/dashboard` | Add a software title configuration to the dashboard
 |
| `DELETE` | `/v2/patch-software-title-configurations/{id}/dashboard` | Remove a software title configuration from the dashboard
 |
| `GET` | `/v2/patch-software-title-configurations/{id}/definitions` | Retrieve Patch Software Title Definitions with the supplied id |
| `GET` | `/v2/patch-software-title-configurations/{id}/dependencies` | Retrieve list of Patch Software Title Configuration Dependencies |
| `GET` | `/v2/patch-software-title-configurations/{id}/export-report` | Export Patch Reporting Data |
| `GET` | `/v2/patch-software-title-configurations/{id}/extension-attributes` | Retrieve Software Title Extension Attributes with the supplied id |
| `GET` | `/v2/patch-software-title-configurations/{id}/history` | Get specified Patch Software Title Configuration history object
 |
| `POST` | `/v2/patch-software-title-configurations/{id}/history` | Add Patch Software Title Configuration history object notes
 |
| `GET` | `/v2/patch-software-title-configurations/{id}/patch-report` | Retrieve Patch Software Title Configuration Patch Report |
| `GET` | `/v2/patch-software-title-configurations/{id}/patch-summary` | Return Active Patch Summary |
| `GET` | `/v2/patch-software-title-configurations/{id}/patch-summary/versions` | Returns patch versions |

#### patchavailabletitles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patchavailabletitles/sourceid/{id}` | Finds all available title from a source by ID |

#### patches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patches` | Finds all patches (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-software-title-configuratio... |
| `GET` | `/patches/id/{id}` | Finds patches by ID (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-software-title-configurat... |
| `POST` | `/patches/id/{id}` | Creates a patch software title (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-software-title... |
| `PUT` | `/patches/id/{id}` | Updates a Patch Software Title by ID (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-software... |
| `DELETE` | `/patches/id/{id}` | Deletes a Patch Software Title by ID (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-software... |
| `GET` | `/patches/id/{id}/version/{version}` | Display computers on a specific version (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-softw... |
| `GET` | `/patches/name/{name}` | Finds the first patch with the name provided (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-... |
| `PUT` | `/patches/name/{name}` | Updates a Patch Software Title by name (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-softwa... |
| `DELETE` | `/patches/name/{name}` | Deletes a Patch Software Title by name (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-softwa... |
| `GET` | `/patches/name/{name}/version/{version}` | Display computers on a specific version (Deprecated - Please transition use to Jamf Pro API endpoint "/v2/patch-softw... |

#### patchexternalsources

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patchexternalsources` | Finds all patch external sources |
| `GET` | `/patchexternalsources/id/{id}` | Finds a patch external source by ID |
| `POST` | `/patchexternalsources/id/{id}` | Create a new patch external source by ID |
| `PUT` | `/patchexternalsources/id/{id}` | Updates a patch external source by ID |
| `DELETE` | `/patchexternalsources/id/{id}` | Deletes a patch external source by ID |
| `GET` | `/patchexternalsources/name/{name}` | Finds the first patch external source with the name provided |
| `POST` | `/patchexternalsources/name/{name}` | Create a new patch external source by name |
| `PUT` | `/patchexternalsources/name/{name}` | Updates a patch external source by name |

#### patchinternalsources

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patchinternalsources` | Finds all patch internal sources |
| `GET` | `/patchinternalsources/id/{id}` | Finds a patch internal source by ID |
| `GET` | `/patchinternalsources/name/{name}` | Finds the first patch internal source with the name provided |

#### patchpolicies

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patchpolicies` | Finds all patch policies. (Deprecated). Please transition use to Jamf Pro API endpoint "/v2/patch-policies". |
| `GET` | `/patchpolicies/id/{id}` | Finds a patch policy by ID |
| `PUT` | `/patchpolicies/id/{id}` | Updates an existing patch policy by ID |
| `DELETE` | `/patchpolicies/id/{id}` | Deletes a patch policy by ID |
| `GET` | `/patchpolicies/id/{id}/subset/{subset}` | Display subsets of information for a patch policy |
| `GET` | `/patchpolicies/softwaretitleconfig/id/{softwaretitleconfigid}` | Finds all patch policies by patch software title configuration ID (Deprecated). Please transition use to Jamf Pro API... |
| `POST` | `/patchpolicies/softwaretitleconfig/id/{softwaretitleconfigid}` | Create a new patch policy associated with a patch software title configuration ID |

#### patchreports

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patchreports/patchsoftwaretitleid/{id}` | Finds patch reports by patch software title ID. (Deprecated) Please transition use to Jamf Pro API endpoint "/v2/patc... |
| `GET` | `/patchreports/patchsoftwaretitleid/{id}/version/{version}` | Display computers for a specific version of a patch report. (Deprecated) Please transition use to Jamf Pro API endpoi... |

#### patchsoftwaretitles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patchsoftwaretitles` | Finds all patch software titles. (Deprecated) Please transition use to Jamf Pro API endpoint "/v2/patch-software-titl... |
| `GET` | `/patchsoftwaretitles/id/{id}` | Finds a patch software titles by ID. (Deprecated) Please transition use to Jamf Pro API endpoint "/v2/patch-software-... |
| `POST` | `/patchsoftwaretitles/id/{id}` | Creates new patch software title by ID. (Deprecated) Please transition use to Jamf Pro API endpoint "/v2/patch-softwa... |
| `PUT` | `/patchsoftwaretitles/id/{id}` | Updates a patch software title by ID. (Deprecated) Please transition use to Jamf Pro API endpoint "/v2/patch-software... |
| `DELETE` | `/patchsoftwaretitles/id/{id}` | Deletes a patch software title by ID. (Deprecated) Please transition use to Jamf Pro API endpoint "/v2/patch-software... |

### External Patch Source API

#### available

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/available` | Get available titles |

#### capabilities

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `PUT` | `/capabilities/{id}` | Update capability |
| `DELETE` | `/capabilities/{id}` | Delete capability |

#### components

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/components/{id}` | Get component |
| `PUT` | `/components/{id}` | Update component |
| `DELETE` | `/components/{id}` | Delete component |
| `POST` | `/components/{id}/criteria` | Create criteria |
| `GET` | `/components/{id}/criteria/autofill` | Get autofill criteria |
| `GET` | `/components/{id}/navigation` | Get navigation |

#### criteria

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `PUT` | `/criteria/{id}` | Update criteria |
| `DELETE` | `/criteria/{id}` | Delete criteria |

#### extensionattributes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/extensionattributes/{id}` | Get extension attribute |
| `PUT` | `/extensionattributes/{id}` | Update extension attribute |
| `DELETE` | `/extensionattributes/{id}` | Delete extension attribute |
| `GET` | `/extensionattributes/{id}/navigation` | Get navigation |

#### killapps

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/killapps/{id}` | Get kill app |
| `PUT` | `/killapps/{id}` | Update kill app |
| `DELETE` | `/killapps/{id}` | Delete kill app |
| `GET` | `/killapps/{id}/navigation` | Get navigation |

#### overrides

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/overrides/killapps/{id}` | Get override kill app |
| `PUT` | `/overrides/killapps/{id}` | Update override kill app |
| `DELETE` | `/overrides/killapps/{id}` | Delete override kill app |
| `GET` | `/overrides/killapps/{id}/navigation` | Get navigation |

#### patches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/patches/{id}` | Get patch |
| `PUT` | `/patches/{id}` | Update patch |
| `DELETE` | `/patches/{id}` | Delete patch |
| `POST` | `/patches/{id}/capabilities` | Create capability |
| `GET` | `/patches/{id}/capabilities/autofill` | Get autofill capabilities |
| `POST` | `/patches/{id}/clone` | Clone patch |
| `POST` | `/patches/{id}/components` | Create component |
| `GET` | `/patches/{id}/components/autofill` | Get autofill components |
| `POST` | `/patches/{id}/killapps` | Create kill app |
| `GET` | `/patches/{id}/killapps/autofill` | Get autofill kill apps |
| `GET` | `/patches/{id}/navigation` | Get navigation |

#### preferences

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/preferences/{key}` | Get preference |
| `PUT` | `/preferences/{key}` | Set preference |
| `DELETE` | `/preferences/{key}` | Delete preference |

#### privileges

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `DELETE` | `/privileges/{id}` | Delete privilege |

#### requirements

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `PUT` | `/requirements/{id}` | Update requirement |
| `DELETE` | `/requirements/{id}` | Delete requirement |

#### softwaretitles

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/softwaretitles` | Get software titles |
| `POST` | `/softwaretitles` | Create software title |
| `GET` | `/softwaretitles/{id}` | Get software title |
| `PUT` | `/softwaretitles/{id}` | Update software title |
| `DELETE` | `/softwaretitles/{id}` | Delete software title |
| `POST` | `/softwaretitles/{id}/extensionattributes` | Create extension attribute |
| `POST` | `/softwaretitles/{id}/patches` | Create patch |
| `GET` | `/softwaretitles/{id}/patches/autofill` | Get autofill patches |
| `POST` | `/softwaretitles/{id}/requirements` | Create requirement |
| `GET` | `/softwaretitles/{id}/requirements/autofill` | Get autofill requirements |

#### sources

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/sources` | Get sources |
| `POST` | `/sources` | Create source |
| `GET` | `/sources/{id}` | Get source |
| `PUT` | `/sources/{id}` | Update source |
| `DELETE` | `/sources/{id}` | Delete source |

#### subscribed

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/subscribed/refresh` | Refresh subscribed titles |
| `GET` | `/subscribed/{id}` | Get subscribed title |
| `GET` | `/subscribed/{id}/definition` | Get definition |
| `GET` | `/subscribed/{id}/overrides` | Get override |
| `PUT` | `/subscribed/{id}/overrides` | Set override |
| `DELETE` | `/subscribed/{id}/overrides` | Delete override |
| `GET` | `/subscribed/{id}/overrides/killapps` | Get kill apps |
| `POST` | `/subscribed/{id}/overrides/killapps` | Create kill app |
| `GET` | `/subscribed/{id}/overrides/killapps/autofill` | Get autofill kill apps |

#### valuelists

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/valuelists/auth/schemes` | Get authentication schemes |
| `GET` | `/valuelists/criteria/names` | Get criteria names |
| `POST` | `/valuelists/criteria/operators` | Get criteria operators |
| `GET` | `/valuelists/criteria/types` | Get criteria types |
| `GET` | `/valuelists/preferences/keys` | Get preference keys |
| `GET` | `/valuelists/preferences/types` | Get preference types |
| `GET` | `/valuelists/privileges/scopes` | Get privilege scopes |
| `GET` | `/valuelists/smtp/encryption` | Get smtp encryption types |

---

## 内容分发与VPP

### Jamf Pro API

#### ebooks

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/ebooks` | Finds all ebooks |
| `GET` | `/ebooks/id/{id}` | Finds ebooks by ID |
| `POST` | `/ebooks/id/{id}` | Creates a new ebook by ID |
| `PUT` | `/ebooks/id/{id}` | Updates an existing ebook by ID |
| `DELETE` | `/ebooks/id/{id}` | Deletes an ebook by ID |
| `GET` | `/ebooks/id/{id}/subset/{subset}` | Finds a subset of data for an ebook by ID |
| `GET` | `/ebooks/name/{name}` | Finds ebooks by name |
| `PUT` | `/ebooks/name/{name}` | Updates an existing ebook by name |
| `DELETE` | `/ebooks/name/{name}` | Deletes an ebook by name |
| `GET` | `/ebooks/name/{name}/subset/{subset}` | Finds a subset of data for ebooks by name |
| `GET` | `/v1/ebooks` | Get Ebook object
 |
| `GET` | `/v1/ebooks/{id}` | Get specified Ebook object
 |
| `GET` | `/v1/ebooks/{id}/scope` | Get specified scope of Ebook object
 |

#### jamf-package

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/jamf-package` | Get the packages for a given Jamf application
 |
| `GET` | `/v2/jamf-package` | Get the packages for a given Jamf application
 |

#### packages

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/packages` | Finds all packages |
| `GET` | `/packages/id/{id}` | Finds packages by ID |
| `POST` | `/packages/id/{id}` | Creates a new package by ID |
| `PUT` | `/packages/id/{id}` | Updates an existing package by ID |
| `DELETE` | `/packages/id/{id}` | Deletes a package by ID |
| `GET` | `/packages/name/{name}` | Finds packages by name |
| `PUT` | `/packages/name/{name}` | Updates an existing package by name |
| `DELETE` | `/packages/name/{name}` | Deletes a package by name |
| `GET` | `/v1/packages` | Retrieve Packages |
| `POST` | `/v1/packages` | Create package |
| `POST` | `/v1/packages/delete-multiple` | Delete multiple packages at once |
| `POST` | `/v1/packages/export` | Export Packages collection
 |
| `GET` | `/v1/packages/{id}` | Get specified Package object
 |
| `PUT` | `/v1/packages/{id}` | Update specified package object
 |
| `DELETE` | `/v1/packages/{id}` | Remove specified package
 |
| `GET` | `/v1/packages/{id}/history` | Get specified Package History object
 |
| `POST` | `/v1/packages/{id}/history` | Add specified Package history object notes
 |
| `POST` | `/v1/packages/{id}/history/export` | Export history object collection in specified format for specified Packages
 |
| `POST` | `/v1/packages/{id}/manifest` | Add a manifest to a package
 |
| `DELETE` | `/v1/packages/{id}/manifest` | Delete the manifest for a specified package
 |
| `POST` | `/v1/packages/{id}/upload` | Upload package |

#### vppaccounts

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/vppaccounts` | Finds all VPP Accounts |
| `GET` | `/vppaccounts/id/{id}` | Finds VPP Account by ID |
| `POST` | `/vppaccounts/id/{id}` | Creates a new VPP account by ID |
| `PUT` | `/vppaccounts/id/{id}` | Updates a VPP account by ID |
| `DELETE` | `/vppaccounts/id/{id}` | Deletes a VPP account by ID |

#### vppassignments

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/vppassignments` | Finds all VPP Assignments |
| `GET` | `/vppassignments/id/{id}` | Finds VPP Assignment by ID |
| `POST` | `/vppassignments/id/{id}` | Creates a new VPP assignment by ID |
| `PUT` | `/vppassignments/id/{id}` | Updates a VPP assignment by ID |
| `DELETE` | `/vppassignments/id/{id}` | Deletes a VPP assignment by ID |

#### vppinvitations

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/vppinvitations` | Finds all VPP Invitations |
| `GET` | `/vppinvitations/id/{id}` | Finds a VPP Invitation by ID |
| `POST` | `/vppinvitations/id/{id}` | Creates a new VPP invitation by ID |
| `PUT` | `/vppinvitations/id/{id}` | Updates a VPP invitation by ID |
| `DELETE` | `/vppinvitations/id/{id}` | Deletes a VPP invitation by ID |
| `GET` | `/vppinvitations/id/{id}/subset/{subset}` | Finds a subset of data for a VPP invitation |

---

## 搜索与报告

### Jamf Pro API

#### advanced-mobile-device-searches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/advanced-mobile-device-searches` | Get Advanced Search objects
 |
| `POST` | `/v1/advanced-mobile-device-searches` | Create Advanced Search object
 |
| `GET` | `/v1/advanced-mobile-device-searches/choices` | Get Mobile Device Advanced Search criteria choices
 |
| `POST` | `/v1/advanced-mobile-device-searches/delete-multiple` | Remove specified Advanced Search objects
 |
| `GET` | `/v1/advanced-mobile-device-searches/{id}` | Get specified Advanced Search object
 |
| `PUT` | `/v1/advanced-mobile-device-searches/{id}` | Get specified Advanced Search object
 |
| `DELETE` | `/v1/advanced-mobile-device-searches/{id}` | Remove specified Advanced Search object
 |

#### advanced-user-content-searches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/advanced-user-content-searches` | Get All Advanced User Content Search objects
 |
| `POST` | `/v1/advanced-user-content-searches` | Create Advanced User Content Search object
 |
| `GET` | `/v1/advanced-user-content-searches/{id}` | Get Specified Advanced User Content Search object
 |
| `PUT` | `/v1/advanced-user-content-searches/{id}` | Get Specified Advanced User Content Search object
 |
| `DELETE` | `/v1/advanced-user-content-searches/{id}` | Remove specified Advanced User Content Search object
 |

#### advancedcomputersearches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/advancedcomputersearches` | Finds all advanced computer searches |
| `GET` | `/advancedcomputersearches/id/{id}` | Finds computer searches by ID |
| `POST` | `/advancedcomputersearches/id/{id}` | Creates a new advanced computer search |
| `PUT` | `/advancedcomputersearches/id/{id}` | Updates an existing advanced computer search by ID |
| `DELETE` | `/advancedcomputersearches/id/{id}` | Deletes a computer search by ID |
| `GET` | `/advancedcomputersearches/name/{name}` | Finds advanced computer searches by name |
| `PUT` | `/advancedcomputersearches/name/{name}` | Updates an existing advanced computer search by name |
| `DELETE` | `/advancedcomputersearches/name/{name}` | Deletes a computer search by name |

#### advancedmobiledevicesearches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/advancedmobiledevicesearches` | Finds all advanced mobile device searches |
| `GET` | `/advancedmobiledevicesearches/id/{id}` | Finds mobile device searches by ID |
| `POST` | `/advancedmobiledevicesearches/id/{id}` | Creates a new advanced mobile device search |
| `PUT` | `/advancedmobiledevicesearches/id/{id}` | Updates an existing advanced mobile device search by ID |
| `DELETE` | `/advancedmobiledevicesearches/id/{id}` | Deletes a mobile device search by ID |
| `GET` | `/advancedmobiledevicesearches/name/{name}` | Finds advanced mobile device searches by name |
| `PUT` | `/advancedmobiledevicesearches/name/{name}` | Updates an existing advanced mobile device search by name |
| `DELETE` | `/advancedmobiledevicesearches/name/{name}` | Deletes a mobile device search by name |

#### advancedusersearches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/advancedusersearches` | Finds all advanced user searches |
| `GET` | `/advancedusersearches/id/{id}` | Finds user searches by ID |
| `POST` | `/advancedusersearches/id/{id}` | Creates a new advanced user search by ID |
| `PUT` | `/advancedusersearches/id/{id}` | Updates an existing advanced user search by ID |
| `DELETE` | `/advancedusersearches/id/{id}` | Deletes a user search by ID |
| `GET` | `/advancedusersearches/name/{name}` | Finds user searches by name |
| `PUT` | `/advancedusersearches/name/{name}` | Updates an existing advanced user search by name |
| `DELETE` | `/advancedusersearches/name/{name}` | Deletes a user search by Name |

#### dashboard

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/dashboard` | Get all the dashboard setup information
 |
| `POST` | `/v1/dashboard/toggle` | Add or remove an object to the Jamf Pro dashboard
 |

#### inventory-information

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/inventory-information` | Get statistics about managed/unmanaged devices and computers in the inventory
 |

#### inventory-preload

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/inventory-preload` | Return all Inventory Preload records
 |
| `POST` | `/inventory-preload` | Create a new Inventory Preload record using JSON or CSV
 |
| `DELETE` | `/inventory-preload` | Delete all Inventory Preload records
 |
| `GET` | `/inventory-preload/csv-template` | Get the Inventory Preload CSV template
 |
| `GET` | `/inventory-preload/history` | Get Inventory Preload history entries
 |
| `POST` | `/inventory-preload/history/notes` | Add Inventory Preload history object notes
 |
| `POST` | `/inventory-preload/validate-csv` | Validate a given CSV file
 |
| `GET` | `/inventory-preload/{id}` | Get an Inventory Preload record
 |
| `PUT` | `/inventory-preload/{id}` | Update an Inventory Preload record
 |
| `DELETE` | `/inventory-preload/{id}` | Delete an Inventory Preload record
 |
| `GET` | `/v1/inventory-preload` | Return all Inventory Preload records
 |
| `POST` | `/v1/inventory-preload` | Create a new Inventory Preload record using JSON or CSV
 |
| `DELETE` | `/v1/inventory-preload` | Delete all Inventory Preload records
 |
| `GET` | `/v1/inventory-preload/csv-template` | Retrieve the Inventory Preload CSV template
 |
| `GET` | `/v1/inventory-preload/history` | Get Inventory Preload history entries
 |
| `POST` | `/v1/inventory-preload/history` | Add Inventory Preload history object notes
 |
| `POST` | `/v1/inventory-preload/validate-csv` | Validate a given CSV file
 |
| `GET` | `/v1/inventory-preload/{id}` | Get an Inventory Preload record
 |
| `PUT` | `/v1/inventory-preload/{id}` | Update an Inventory Preload record
 |
| `DELETE` | `/v1/inventory-preload/{id}` | Delete an Inventory Preload record
 |
| `GET` | `/v2/inventory-preload/csv` | Download all Inventory Preload records |
| `POST` | `/v2/inventory-preload/csv` | Create one or more new Inventory Preload records using CSV
 |
| `GET` | `/v2/inventory-preload/csv-template` | Download the Inventory Preload CSV template |
| `POST` | `/v2/inventory-preload/csv-validate` | Validate a given CSV file
 |
| `GET` | `/v2/inventory-preload/ea-columns` | Retrieve a list of extension attribute columns
 |
| `POST` | `/v2/inventory-preload/export` | Export a collection of inventory preload records
 |
| `GET` | `/v2/inventory-preload/history` | Get Inventory Preload history entries
 |
| `POST` | `/v2/inventory-preload/history` | Add Inventory Preload history object notes |
| `GET` | `/v2/inventory-preload/records` | Return all Inventory Preload records |
| `POST` | `/v2/inventory-preload/records` | Create a new Inventory Preload record using JSON |
| `POST` | `/v2/inventory-preload/records/delete-all` | Delete all Inventory Preload records
 |
| `GET` | `/v2/inventory-preload/records/{id}` | Get an Inventory Preload record |
| `PUT` | `/v2/inventory-preload/records/{id}` | Update an Inventory Preload record |
| `DELETE` | `/v2/inventory-preload/records/{id}` | Delete an Inventory Preload record
 |

#### savedsearches

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/savedsearches` | Finds all saved searches (Deprecated - use advancedcomputersearches, advancedmobiledevicesearches and advancedusersea... |
| `GET` | `/savedsearches/id/{id}` | Finds saved searches by ID (Deprecated - use advancedcomputersearches, advancedmobiledevicesearches and advancedusers... |
| `GET` | `/savedsearches/name/{name}` | Finds saved searches by name (Deprecated - use advancedcomputersearches, advancedmobiledevicesearches and advanceduse... |

---

## 脚本与自动化

### Jamf Pro API

#### commandflush

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `DELETE` | `/commandflush` | Flushes commands based on information specified in an XML file |
| `DELETE` | `/commandflush/{idtype}/id/{id}/status/{status}` | Flushes commands for devices |

#### scheduler

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/scheduler/jobs` | Retrieve all Jamf Pro Scheduler jobs |
| `GET` | `/v1/scheduler/jobs/{jobKey}/triggers` | Retrieve all triggers for a Jamf Pro Scheduler job |
| `GET` | `/v1/scheduler/summary` | Retrieve a summary of the Jamf Pro Scheduler |

#### scripts

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/scripts` | Finds all scripts |
| `GET` | `/scripts/id/{id}` | Finds scripts by ID |
| `POST` | `/scripts/id/{id}` | Creates a new script by ID |
| `PUT` | `/scripts/id/{id}` | Updates an existing script by ID |
| `DELETE` | `/scripts/id/{id}` | Deletes a script by ID |
| `GET` | `/scripts/name/{name}` | Finds scripts by name |
| `PUT` | `/scripts/name/{name}` | Updates an existing script by name |
| `DELETE` | `/scripts/name/{name}` | Deletes a script by name |
| `GET` | `/v1/scripts` | Search for sorted and paged Scripts
 |
| `POST` | `/v1/scripts` | Create a Script
 |
| `GET` | `/v1/scripts/{id}` | Retrieve a full script object
 |
| `PUT` | `/v1/scripts/{id}` | Replace the script at the id with the supplied information
 |
| `DELETE` | `/v1/scripts/{id}` | Delete a Script at the specified id
 |
| `GET` | `/v1/scripts/{id}/download` | Download a text file of the Script contents
 |
| `GET` | `/v1/scripts/{id}/history` | Get specified Script history object
 |
| `POST` | `/v1/scripts/{id}/history` | Add specified Script history object notes
 |

#### webhooks

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/webhooks` | Finds all webhooks |
| `GET` | `/webhooks/id/{id}` | Finds webhooks by ID |
| `POST` | `/webhooks/id/{id}` | Creates a new webhook by ID |
| `PUT` | `/webhooks/id/{id}` | Updates an existing webhook by ID |
| `DELETE` | `/webhooks/id/{id}` | Deletes a webhook by ID |
| `GET` | `/webhooks/name/{name}` | Finds webhooks by name |
| `PUT` | `/webhooks/name/{name}` | Updates an existing webhook by name |
| `DELETE` | `/webhooks/name/{name}` | Deletes a webhook by name |

---

## 自助服务

### Jamf Pro API

#### branding-images

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/branding-images/download/{id}` | Download a self service branding image
 |

#### login-customization

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/login-customization` | Get current login disclaimer settings |
| `PUT` | `/v1/login-customization` | Update current login disclaimer settings. |

#### self-service

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/self-service/branding/images` | Upload an image
 |
| `GET` | `/v1/self-service/branding/ios` | Search for sorted and paged iOS branding configurations
 |
| `POST` | `/v1/self-service/branding/ios` | Create a Self Service iOS branding configuration with the supplied
 |
| `GET` | `/v1/self-service/branding/ios/{id}` | Read a single Self Service iOS branding configuration indicated by the provided id
 |
| `PUT` | `/v1/self-service/branding/ios/{id}` | Update a Self Service iOS branding configuration with the supplied details
 |
| `DELETE` | `/v1/self-service/branding/ios/{id}` | Delete the Self Service iOS branding configuration indicated by the provided id
 |
| `GET` | `/v1/self-service/branding/macos` | Search for sorted and paged macOS branding configurations
 |
| `POST` | `/v1/self-service/branding/macos` | Create a Self Service macOS branding configuration with the supplied
 |
| `GET` | `/v1/self-service/branding/macos/{id}` | Read a single Self Service macOS branding configuration indicated by the provided id
 |
| `PUT` | `/v1/self-service/branding/macos/{id}` | Update a Self Service macOS branding configuration with the supplied details
 |
| `DELETE` | `/v1/self-service/branding/macos/{id}` | Delete the Self Service macOS branding configuration indicated by the provided id
 |
| `GET` | `/v1/self-service/settings` | Get an object representation of Self Service settings
 |
| `PUT` | `/v1/self-service/settings` | Put an object representation of Self Service settings
 |
| `GET` | `/v1/self-service/settings/history` | Get a page of Self Service settings history
 |
| `POST` | `/v1/self-service/settings/history` | Add Self Service settings history notes
 |

#### self-service-plus

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/self-service-plus/feature-toggle/enabled` | Determines if Self Service Plus feature toggle is enabled. |
| `GET` | `/v1/self-service-plus/settings` | Get Self Service Plus settings. |
| `PUT` | `/v1/self-service-plus/settings` | Save Self Service Plus settings. |

---

## 云服务与集成

### Jamf Pro API

#### cloud-azure

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/cloud-azure` | Create Azure Cloud Identity Provider configuration |
| `GET` | `/v1/cloud-azure/defaults/mappings` | Get default mappings |
| `GET` | `/v1/cloud-azure/defaults/server-configuration` | Get default server configuration |
| `GET` | `/v1/cloud-azure/{id}` | Get Azure Cloud Identity Provider configuration with given ID. |
| `PUT` | `/v1/cloud-azure/{id}` | Update Azure Cloud Identity Provider configuration |
| `DELETE` | `/v1/cloud-azure/{id}` | Delete Cloud Identity Provider configuration. |

#### cloud-idp

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/cloud-idp` | Get information about all Cloud Identity Providers configurations. |
| `POST` | `/v1/cloud-idp/export` | Export Cloud Identity Providers collection
 |
| `GET` | `/v1/cloud-idp/{id}` | Get Cloud Identity Provider configuration with given ID. |
| `GET` | `/v1/cloud-idp/{id}/history` | Get Cloud Identity Provider history |
| `POST` | `/v1/cloud-idp/{id}/history` | Add Cloud Identity Provider history note |
| `POST` | `/v1/cloud-idp/{id}/test-group` | Get group test search |
| `POST` | `/v1/cloud-idp/{id}/test-user` | Get user test search |
| `POST` | `/v1/cloud-idp/{id}/test-user-membership` | Get membership test search |

#### cloud-information

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/cloud-information` | Retrieve information related to cloud setup.
 |

#### csa

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/csa/tenant-id` | Returns the CSA tenant ID. |
| `GET` | `/v1/csa/token` | Get details regarding the CSA token exchange
 |
| `DELETE` | `/v1/csa/token` | Delete the CSA token exchange - This will disable Jamf Pro's ability to authenticate with cloud-hosted services
 |

#### impact-alert-notification-settings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/impact-alert-notification-settings` | Get Impact Alert Notification Settings |
| `PUT` | `/v1/impact-alert-notification-settings` | Update Impact Alert Notification Settings |

#### jamf-connect

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/jamf-connect` | Get the Jamf Connect settings that you have access to see
 |
| `GET` | `/v1/jamf-connect/config-profiles` | Search for config profiles linked to Jamf Connect
 |
| `PUT` | `/v1/jamf-connect/config-profiles/{id}` | Update the way the Jamf Connect app gets updated on computers within scope of the associated configuration profile.
 |
| `GET` | `/v1/jamf-connect/deployments/{id}/tasks` | Search for deployment tasks for a config profile linked to Jamf Connect
 |
| `POST` | `/v1/jamf-connect/deployments/{id}/tasks/retry` | Request a retry of Connect install tasks
 |
| `GET` | `/v1/jamf-connect/history` | Get Jamf Connect history
 |
| `POST` | `/v1/jamf-connect/history` | Add Jamf Connect history notes
 |

#### jamf-protect

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/jamf-protect` | Jamf Protect integration settings |
| `PUT` | `/v1/jamf-protect` | Jamf Protect integration settings |
| `DELETE` | `/v1/jamf-protect` | Delete Jamf Protect API registration. |
| `GET` | `/v1/jamf-protect/deployments/{id}/tasks` | Search for deployment tasks for a config profile linked to Jamf Protect
 |
| `POST` | `/v1/jamf-protect/deployments/{id}/tasks/retry` | Request a retry of Protect install tasks
 |
| `GET` | `/v1/jamf-protect/history` | Get Jamf Protect history
 |
| `POST` | `/v1/jamf-protect/history` | Add Jamf Protect history notes
 |
| `GET` | `/v1/jamf-protect/plans` | Get all of the previously synced Jamf Protect Plans with information about their associated configuration profile |
| `POST` | `/v1/jamf-protect/plans/sync` | Sync Plans with Jamf Protect |
| `POST` | `/v1/jamf-protect/register` | Register a Jamf Protect API configuration with Jamf Pro |

#### jamf-remote-assist

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/jamf-remote-assist/session` | Gets session history items.
 |
| `GET` | `/v1/jamf-remote-assist/session/{id}` | Gets single session history item.
 |
| `GET` | `/v2/jamf-remote-assist/session` | Gets session history items.
 |
| `POST` | `/v2/jamf-remote-assist/session/export` | Export Jamf Remote Assist sessions history
 |
| `GET` | `/v2/jamf-remote-assist/session/{id}` | Gets single session history item.
 |

#### parent-app

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/parent-app` | Get the current Jamf Parent app settings
 |
| `PUT` | `/v1/parent-app` | Update Jamf Parent app settings
 |
| `GET` | `/v1/parent-app/history` | Get Jamf Parent app settings history
 |
| `POST` | `/v1/parent-app/history` | Add Jamf Parent app settings history notes
 |

#### preview

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/preview/remote-administration-configurations` | Get information about all remote administration configurations. |
| `POST` | `/preview/remote-administration-configurations/team-viewer` | Create Team Viewer Remote Administration connection configuration |
| `GET` | `/preview/remote-administration-configurations/team-viewer/{configurationId}/sessions` | Get a paginated list of sessions
 |
| `POST` | `/preview/remote-administration-configurations/team-viewer/{configurationId}/sessions` | Create a new session |
| `GET` | `/preview/remote-administration-configurations/team-viewer/{configurationId}/sessions/{sessionId}` | Get a session by its ID
 |
| `POST` | `/preview/remote-administration-configurations/team-viewer/{configurationId}/sessions/{sessionId}/close` | Close a session |
| `POST` | `/preview/remote-administration-configurations/team-viewer/{configurationId}/sessions/{sessionId}/resend-notification` | Resend nofications for a session |
| `GET` | `/preview/remote-administration-configurations/team-viewer/{configurationId}/sessions/{sessionId}/status` | Get a session status by its ID
 |
| `GET` | `/preview/remote-administration-configurations/team-viewer/{id}` | Get Team Viewer Remote Administration connection configuration |
| `PATCH` | `/preview/remote-administration-configurations/team-viewer/{id}` | Update Team Viewer Remote Administration connection configuration |
| `DELETE` | `/preview/remote-administration-configurations/team-viewer/{id}` | Delete Team Viewer Remote Administration connection configuration |
| `GET` | `/preview/remote-administration-configurations/team-viewer/{id}/status` | Get Team Viewer Remote Administration connection status |

---

## 组织结构与分类

### Jamf Pro API

#### buildings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/buildings` | Finds all buildings |
| `GET` | `/buildings/id/{id}` | Finds buildings by ID |
| `POST` | `/buildings/id/{id}` | Creates a new building |
| `PUT` | `/buildings/id/{id}` | Updates an existing building by ID |
| `DELETE` | `/buildings/id/{id}` | Deletes a building by ID |
| `GET` | `/buildings/name/{name}` | Finds buildings by name |
| `PUT` | `/buildings/name/{name}` | Updates an existing building by name |
| `DELETE` | `/buildings/name/{name}` | Deletes a building by name |
| `GET` | `/v1/buildings` | Search for sorted and paged Buildings
 |
| `POST` | `/v1/buildings` | Create Building record
 |
| `POST` | `/v1/buildings/delete-multiple` | Delete multiple Buildings by their ids
 |
| `POST` | `/v1/buildings/export` | Export Buildings collection
 |
| `GET` | `/v1/buildings/{id}` | Get specified Building object
 |
| `PUT` | `/v1/buildings/{id}` | Update specified Building object
 |
| `DELETE` | `/v1/buildings/{id}` | Remove specified Building record
 |
| `GET` | `/v1/buildings/{id}/history` | Get specified Building History object
 |
| `POST` | `/v1/buildings/{id}/history` | Add specified Building history object notes
 |
| `POST` | `/v1/buildings/{id}/history/export` | Export history object collection in specified format for specified Buildings
 |

#### categories

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/categories` | Finds all categories |
| `GET` | `/categories/id/{id}` | Finds categories by ID |
| `POST` | `/categories/id/{id}` | Creates a new category by ID |
| `PUT` | `/categories/id/{id}` | Updates an existing category by ID |
| `DELETE` | `/categories/id/{id}` | Deletes a category by ID |
| `GET` | `/categories/name/{name}` | Finds categories by name |
| `PUT` | `/categories/name/{name}` | Updates an existing category by name |
| `DELETE` | `/categories/name/{name}` | Deletes a category by name |
| `GET` | `/v1/categories` | Get Category objects
 |
| `POST` | `/v1/categories` | Create Category record
 |
| `POST` | `/v1/categories/delete-multiple` | Delete multiple Categories by their IDs
 |
| `GET` | `/v1/categories/{id}` | Get specified Category object
 |
| `PUT` | `/v1/categories/{id}` | Update specified Category object
 |
| `DELETE` | `/v1/categories/{id}` | Remove specified Category record
 |
| `GET` | `/v1/categories/{id}/history` | Get specified Category history object
 |
| `POST` | `/v1/categories/{id}/history` | Add specified Category history object notes
 |

#### departments

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/departments` | Finds all departments |
| `GET` | `/departments/id/{id}` | Finds departments by ID |
| `POST` | `/departments/id/{id}` | Creates a new department by ID |
| `PUT` | `/departments/id/{id}` | Updates an existing department by ID |
| `DELETE` | `/departments/id/{id}` | Deletes a department by ID |
| `GET` | `/departments/name/{name}` | Finds departments by name |
| `PUT` | `/departments/name/{name}` | Updates an existing department by name |
| `DELETE` | `/departments/name/{name}` | Deletes a department by name |
| `GET` | `/v1/departments` | Search for Departments
 |
| `POST` | `/v1/departments` | Create department record
 |
| `POST` | `/v1/departments/delete-multiple` | Deletes all departments by ids passed in body
 |
| `GET` | `/v1/departments/{id}` | Get specified Department object
 |
| `PUT` | `/v1/departments/{id}` | Update specified department object
 |
| `DELETE` | `/v1/departments/{id}` | Remove specified department record
 |
| `GET` | `/v1/departments/{id}/history` | Get specified Department history object
 |
| `POST` | `/v1/departments/{id}/history` | Add specified Department history object notes
 |

#### groups

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/groups` | Returns group information for all Mobile Device and Computer groups |
| `GET` | `/v1/groups/{id}` | Returns group information for the given platform UUID |
| `PATCH` | `/v1/groups/{id}` | Update a group by platform UUID |
| `DELETE` | `/v1/groups/{id}` | Delete a group by platform UUID |

#### icon

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/icon` | Upload an icon
 |
| `GET` | `/v1/icon/download/{id}` | Download a self service icon
 |
| `GET` | `/v1/icon/{id}` | Get an icon
 |

#### locales

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/locales` | Return locales that can be used in other features
 |

#### sites

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/sites` | Finds all sites |
| `GET` | `/sites/id/{id}` | Finds sites by ID |
| `POST` | `/sites/id/{id}` | Creates a new site by ID |
| `PUT` | `/sites/id/{id}` | Updates an existing site by ID |
| `DELETE` | `/sites/id/{id}` | Deletes a site by ID |
| `GET` | `/sites/name/{name}` | Finds sites by name |
| `PUT` | `/sites/name/{name}` | Updates an existing site by name |
| `DELETE` | `/sites/name/{name}` | Deletes a site by name |
| `GET` | `/v1/sites` | Find all sites
 |
| `GET` | `/v1/sites/{id}/objects` | Find and filter site objects for a site ID
 |

#### time-zones

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/time-zones` | Return information about the currently supported Time Zones
 |

---

## 网络与基础设施

### Jamf Pro API

#### cache-settings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/cache-settings` | Get Cache Settings
 |
| `PUT` | `/v1/cache-settings` | Update Cache Settings
 |

#### cloud-distribution-point

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/cloud-distribution-point` | Get the cloud distribution point Details.
 |
| `POST` | `/v1/cloud-distribution-point` | Create cloud distribution point |
| `PATCH` | `/v1/cloud-distribution-point` | Update specific fields on a cloud distribution point |
| `DELETE` | `/v1/cloud-distribution-point` | Delete cloud distribution point. |
| `POST` | `/v1/cloud-distribution-point/fail-upload/{id}` | Marks a specific file upload as failed for the currently configured cloud distribution point.
 |
| `GET` | `/v1/cloud-distribution-point/files` | Get the cloud distribution point Inventory files details |
| `GET` | `/v1/cloud-distribution-point/history` | Get cloud distribution point history details |
| `POST` | `/v1/cloud-distribution-point/history` | Add specified cloud distribution point history object notes |
| `POST` | `/v1/cloud-distribution-point/refresh-inventory` | Updates inventory data for the currently configured cloud distribution point.
 |
| `GET` | `/v1/cloud-distribution-point/test-connection` | Get the cloud distribution point test connection details.
 |
| `GET` | `/v1/cloud-distribution-point/upload-capability` | Finds specific information for the currently configured cloud distribution point.
 |

#### distribution-points

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/distribution-points` | Finds all Distribution Points |
| `POST` | `/v1/distribution-points` | Create distribution point |
| `POST` | `/v1/distribution-points/delete-multiple` | Delete multiple distribution points at once |
| `GET` | `/v1/distribution-points/{id}` | Get specified distribution point
 |
| `PUT` | `/v1/distribution-points/{id}` | Update specified distribution point object
 |
| `PATCH` | `/v1/distribution-points/{id}` | Update specified distribution point object
 |
| `DELETE` | `/v1/distribution-points/{id}` | Remove specified distribution point
 |
| `GET` | `/v1/distribution-points/{id}/history` | Get specified distribution point History object
 |
| `POST` | `/v1/distribution-points/{id}/history` | Add specified distribution point History object notes
 |

#### distributionpoints

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/distributionpoints` | Finds all distribution points |
| `GET` | `/distributionpoints/id/{id}` | Finds distribution points by ID |
| `POST` | `/distributionpoints/id/{id}` | Creates a new distribution point by ID |
| `PUT` | `/distributionpoints/id/{id}` | Updates an existing distribution point by ID |
| `DELETE` | `/distributionpoints/id/{id}` | Deletes a distribution point by ID |
| `GET` | `/distributionpoints/name/{name}` | Finds distribution points by name |
| `PUT` | `/distributionpoints/name/{name}` | Updates an existing distribution point by name |
| `DELETE` | `/distributionpoints/name/{name}` | Deletes a distribution point by name |

#### gsx-connection

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/gsx-connection` | Finds the Jamf Pro GSX Connection information
 |
| `PUT` | `/v1/gsx-connection` | Updates Jamf Pro GSX Connection information
 |
| `PATCH` | `/v1/gsx-connection` | Updates Jamf Pro GSX Connection information
 |
| `GET` | `/v1/gsx-connection/history` | Get specified GSX Connection History object
 |
| `POST` | `/v1/gsx-connection/history` | Add specified GSX Connection history object notes
 |
| `POST` | `/v1/gsx-connection/test` | Test functionality of an GSX Connection |

#### gsxconnection

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/gsxconnection` | Finds the Jamf Pro GSX connection information |
| `PUT` | `/gsxconnection` | Updates the Jamf Pro GSX connection information |

#### infrastructuremanager

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/infrastructuremanager` | Find all Infrastructure Managers |
| `GET` | `/infrastructuremanager/id/{id}` | Finds infrastructure manager by ID |
| `PUT` | `/infrastructuremanager/id/{id}` | Updates an existing infrastructure manager by ID |

#### jcds

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/jcds/files` | Retrieve a list of files and file metadata from the Jamf Cloud Distribution Service |
| `POST` | `/v1/jcds/files` | Initiate an upload to the Jamf Cloud Distribution Service |
| `GET` | `/v1/jcds/files/{fileName}` | Retrieve a download URL for a specific file from the Jamf Cloud Distribution Service |
| `DELETE` | `/v1/jcds/files/{fileName}` | Delete a file from the Jamf Cloud Distribution Service |
| `POST` | `/v1/jcds/refresh-inventory` | Refreshes the inventory and status of uploads in Jamf Pro. This will update the 
status of uploads in the Jamf Pro da... |
| `POST` | `/v1/jcds/renew-credentials` | Renew credentials for an upload to the Jamf Cloud Distribution Service |

#### networksegments

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/networksegments` | Finds all network segments |
| `GET` | `/networksegments/id/{id}` | Finds network segments by ID |
| `POST` | `/networksegments/id/{id}` | Creates a new network segment by ID |
| `PUT` | `/networksegments/id/{id}` | Updates an existing network segment by ID |
| `DELETE` | `/networksegments/id/{id}` | Deletes a network segment by ID |
| `GET` | `/networksegments/name/{name}` | Finds network segments by name |
| `PUT` | `/networksegments/name/{name}` | Updates an existing network segment by name |
| `DELETE` | `/networksegments/name/{name}` | Deletes a network segment by name |

#### smtp-server

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/smtp-server/history` | Get specified SMTP Server history object
 |
| `POST` | `/v1/smtp-server/history` | Add SMTP Server history object notes
 |
| `POST` | `/v1/smtp-server/test` | Test functionality of an SMTP Server |
| `GET` | `/v2/smtp-server` | Finds the Jamf Pro SMTP Server information
 |
| `PUT` | `/v2/smtp-server` | Updates Jamf Pro SMTP Server information
 |

#### smtpserver

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/smtpserver` | Finds the Jamf Pro SMTP server information |
| `PUT` | `/smtpserver` | Updates the Jamf Pro SMTP server information |

#### softwareupdateservers

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/softwareupdateservers` | Finds all software update servers |
| `GET` | `/softwareupdateservers/id/{id}` | Finds software update servers by ID |
| `POST` | `/softwareupdateservers/id/{id}` | Creates a new software update server by ID |
| `PUT` | `/softwareupdateservers/id/{id}` | Updates an existing software update server by ID |
| `DELETE` | `/softwareupdateservers/id/{id}` | Deletes a software update server by ID |
| `GET` | `/softwareupdateservers/name/{name}` | Finds software update servers by name |
| `PUT` | `/softwareupdateservers/name/{name}` | Updates an existing software update server by name |
| `DELETE` | `/softwareupdateservers/name/{name}` | Deletes a software update server by name |

### External Patch Source API

#### smtpserver

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/smtpserver` | Get smtp server |
| `POST` | `/smtpserver` | Test smtp server |
| `PUT` | `/smtpserver` | Update smtp server |
| `DELETE` | `/smtpserver` | Delete smtp server |

---

## 外围设备与打印

### Jamf Pro API

#### dock-items

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/dock-items` | Create a DockItem
 |
| `GET` | `/v1/dock-items/{id}` | Retrieve a full dockItem object
 |
| `PUT` | `/v1/dock-items/{id}` | Replace the dockItem at the id with the supplied information
 |
| `DELETE` | `/v1/dock-items/{id}` | Delete a DockItem at the specified id
 |

#### dockitems

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/dockitems` | Finds all dock items |
| `GET` | `/dockitems/id/{id}` | Finds dock items by ID |
| `POST` | `/dockitems/id/{id}` | Creates a new dock item by ID |
| `PUT` | `/dockitems/id/{id}` | Updates an existing dock item by ID |
| `DELETE` | `/dockitems/id/{id}` | Deletes a dock item by ID |
| `GET` | `/dockitems/name/{name}` | Finds dock items by name |
| `PUT` | `/dockitems/name/{name}` | Updates an existing dock item by name |
| `DELETE` | `/dockitems/name/{name}` | Deletes a dock item by name |

#### peripherals

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/peripherals` | Finds all peripherals |
| `GET` | `/peripherals/id/{id}` | Finds peripherals by ID |
| `POST` | `/peripherals/id/{id}` | Creates a new peripheral by ID |
| `PUT` | `/peripherals/id/{id}` | Updates an existing peripheral by ID |
| `DELETE` | `/peripherals/id/{id}` | Deletes a peripheral by ID |
| `GET` | `/peripherals/id/{id}/subset/{subset}` | Finds a subset of data for a peripheral |

#### peripheraltypes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/peripheraltypes` | Finds all peripheral types |
| `GET` | `/peripheraltypes/id/{id}` | Finds peripheral types by ID |
| `POST` | `/peripheraltypes/id/{id}` | Creates a new peripheral by ID |
| `PUT` | `/peripheraltypes/id/{id}` | Updates an existing peripheral by ID |
| `DELETE` | `/peripheraltypes/id/{id}` | Deletes a peripheral by ID |

#### printers

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/printers` | Finds all printers |
| `GET` | `/printers/id/{id}` | Finds printers by ID |
| `POST` | `/printers/id/{id}` | Creates a new printer by ID |
| `PUT` | `/printers/id/{id}` | Updates an existing printer by ID |
| `DELETE` | `/printers/id/{id}` | Deletes a printer by ID |
| `GET` | `/printers/name/{name}` | Finds printers by name |
| `PUT` | `/printers/name/{name}` | Updates an existing printer by name |
| `DELETE` | `/printers/name/{name}` | Deletes a printer by name |

#### removablemacaddresses

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/removablemacaddresses` | Finds all removable Mac addresses |
| `GET` | `/removablemacaddresses/id/{id}` | Finds removable Mac addresses by ID |
| `POST` | `/removablemacaddresses/id/{id}` | Creates a new removable Mac address by ID |
| `PUT` | `/removablemacaddresses/id/{id}` | Updates an existing removable Mac address by ID |
| `DELETE` | `/removablemacaddresses/id/{id}` | Deletes a removable Mac address by ID |
| `GET` | `/removablemacaddresses/name/{name}` | Finds removable Mac addresses by name |
| `PUT` | `/removablemacaddresses/name/{name}` | Updates an existing removable Mac address by name |
| `DELETE` | `/removablemacaddresses/name/{name}` | Deletes a removable Mac address by name |

---

## 医疗与定位服务

### Jamf Pro API

#### healthcarelistener

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/healthcarelistener` | Find all Healthcare Listeners |
| `GET` | `/healthcarelistener/id/{id}` | Finds healthcare listener by ID |
| `PUT` | `/healthcarelistener/id/{id}` | Updates an existing healthcare listener by ID |

#### healthcarelistenerrule

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/healthcarelistenerrule` | Find all Healthcare Listener rules |
| `GET` | `/healthcarelistenerrule/id/{id}` | Finds Healthcare Listener rules by ID |
| `POST` | `/healthcarelistenerrule/id/{id}` | Creates a new Healthcare Listener rule |
| `PUT` | `/healthcarelistenerrule/id/{id}` | Updates an existing Healthcare Listener rule by ID |

#### ibeacons

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/ibeacons` | Finds all iBeacon regions |
| `GET` | `/ibeacons/id/{id}` | Finds iBeacon regions by ID |
| `POST` | `/ibeacons/id/{id}` | Creates a new iBeacon region by ID |
| `PUT` | `/ibeacons/id/{id}` | Updates an existing iBeacon region by ID |
| `DELETE` | `/ibeacons/id/{id}` | Deletes an iBeacon region by ID |
| `GET` | `/ibeacons/name/{name}` | Finds iBeacon regions by name |
| `PUT` | `/ibeacons/name/{name}` | Updates an existing iBeacon region by name |
| `DELETE` | `/ibeacons/name/{name}` | Deletes an iBeacon region by name |

---

## 教育管理

### Jamf Pro API

#### classes

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/classes` | Finds all classes |
| `GET` | `/classes/id/{id}` | Finds classes by ID |
| `POST` | `/classes/id/{id}` | Creates a new class by ID |
| `PUT` | `/classes/id/{id}` | Updates an existing class by ID |
| `DELETE` | `/classes/id/{id}` | Deletes a class by ID |
| `GET` | `/classes/name/{name}` | Finds classes by name |
| `PUT` | `/classes/name/{name}` | Updates an existing class by name |
| `DELETE` | `/classes/name/{name}` | Deletes a class by name |

#### teacher-app

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/teacher-app` | Get the Jamf Teacher settings that you have access to see
 |
| `PUT` | `/v1/teacher-app` | Update a Jamf Teacher settings object
 |
| `GET` | `/v1/teacher-app/history` | Get Jamf Teacher app settings history
 |
| `POST` | `/v1/teacher-app/history` | Add Jamf Teacher app settings history notes
 |

---

## 系统配置

### Jamf Pro API

#### activation-code

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `PUT` | `/v1/activation-code` | Updates Activation Code |
| `GET` | `/v1/activation-code/history` | Get Activation Code history object |
| `POST` | `/v1/activation-code/history` | Add Activation Code object note
 |
| `POST` | `/v1/activation-code/history/export` | Export history object collection in specified format for Activation Code
 |
| `PATCH` | `/v1/activation-code/organization-name` | Updates Organization Name |

#### activationcode

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/activationcode` | Finds the Jamf Pro activation code |
| `PUT` | `/activationcode` | Updates the Jamf Pro activation code |

#### health-check

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/health-check` | Get Jamf Pro API status |

#### health-status

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/health-status` | Retrieve request acceptance ratios for this Jamf Pro node |

#### jamf-pro-information

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v2/jamf-pro-information` | Get basic information about the Jamf Pro Server
 |

#### jamf-pro-server-url

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/jamf-pro-server-url` | Get Jamf Pro Server URL settings
 |
| `PUT` | `/v1/jamf-pro-server-url` | Update Jamf Pro Server URL settings
 |
| `GET` | `/v1/jamf-pro-server-url/history` | Get Jamf Pro Server URL settings history
 |
| `POST` | `/v1/jamf-pro-server-url/history` | Add Jamf Pro Server URL settings history notes
 |

#### jamf-pro-version

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/jamf-pro-version` | Return information about the Jamf Pro including the current version
 |

#### log-flushing

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/log-flushing` | Get log flushing settings |
| `GET` | `/v1/log-flushing/task` | Get log flushing tasks |
| `POST` | `/v1/log-flushing/task` | Queue a log flushing task |
| `GET` | `/v1/log-flushing/task/{id}` | Get log flushing task |
| `DELETE` | `/v1/log-flushing/task/{id}` | Cancels a log flushing task |

#### logflush

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `DELETE` | `/logflush` | Flushes a log specified in an XML file |
| `DELETE` | `/logflush/{log}/id/{id}/interval/{interval}` | Flushes a single log for a given interval |
| `DELETE` | `/logflush/{log}/interval/{interval}` | Flushes all logs for a given interval |

#### notifications

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/v1/notifications` | Get Notifications for user and site
 |
| `DELETE` | `/v1/notifications/{type}/{id}` | Delete Notifications
 |

#### settings

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/settings/issueTomcatSslCertificate` | Generate a SSL Certificate using Jamf Certificate Authority
 |

#### startup-status

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `GET` | `/startup-status` | Retrieve information about application startup
 |

#### system

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/v1/system/initialize` | Set up fresh installed Jamf Pro Server
 |
| `POST` | `/v1/system/initialize-database-connection` | Provide Database Password during startup
 |
| `POST` | `/v1/system/platform-initialize` | Set up fresh installed Jamf Pro Server for Platform
 |

---

## 文件上传

### Jamf Pro API

#### fileuploads

| 方法 | 端点路径 | 用途说明 |
|------|----------|----------|
| `POST` | `/fileuploads/{resource}/{idType}/{id}` | Creates file attachments in Jamf Pro |
