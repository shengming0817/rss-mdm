//! Product authorization follows real native operations, independent of execution families.
use super::Task;
use crate::{Error, authorization::Permission as P};
use std::collections::BTreeSet;

pub(super) fn required(task: &Task) -> Result<Vec<P>, Error> {
    let mut permissions = BTreeSet::new();
    match task {
        Task::Windows { request } => match request {
            rss_mdm_windows_mdm::native::Execution::Msi { job } => {
                rss_mdm_windows_mdm::software::Installer::new(job.clone())
                    .map_err(|_| Error::Malformed)?;
                permissions.insert(P::SoftwareDeploy);
            }
            rss_mdm_windows_mdm::native::Execution::SyncMl { request } => {
                request.command_count().map_err(|_| Error::Malformed)?;
                request.validate_poll().map_err(|_| Error::Malformed)?;
                windows(request, &mut permissions)?;
            }
        },
        Task::Macos { request } => {
            use rss_mdm_apple_mdm::native::request::Request as A;
            match request {
                A::Command { command } => {
                    permissions.insert(apple_command(&command.request_type)?);
                    command.fields.to_plist().map_err(|_| Error::Malformed)?;
                }
                A::InstallProfile { profile } => {
                    permissions.insert(P::ConfigurationWrite);
                    for payload in &profile.payloads {
                        permissions.insert(apple_profile(&payload.schema)?);
                    }
                }
                A::RemoveProfile { .. } => {
                    permissions.insert(P::ConfigurationWrite);
                }
                A::Declarations { declarations } => {
                    if declarations.len() > 4096 {
                        return Err(Error::Malformed);
                    }
                    permissions.insert(P::ConfigurationWrite);
                    for declaration in declarations {
                        let ty = declaration.declaration_type.as_str();
                        if ty.contains("softwareupdate") {
                            permissions.insert(P::DeviceUpdate);
                        }
                        if ty.contains("app.managed") || ty.contains("package") {
                            permissions.insert(P::SoftwareDeploy);
                        }
                        if ty.contains("credential") || ty.contains("identity") {
                            permissions.insert(P::SecurityOperate);
                        }
                        if ty.contains("account") {
                            permissions.insert(P::AccountWrite);
                        }
                    }
                }
            }
        }
    }
    Ok(permissions.into_iter().collect())
}
fn apple_profile(schema: &str) -> Result<P, Error> {
    Ok(match schema {
        "mdm/profiles/GlobalPreferences.yaml"
        | "mdm/profiles/com.apple.MCX(EnergySaver).yaml"
        | "mdm/profiles/com.apple.MCX(Mobility).yaml"
        | "mdm/profiles/com.apple.MCX(TimeServer).yaml"
        | "mdm/profiles/com.apple.desktop.yaml"
        | "mdm/profiles/com.apple.dock.yaml"
        | "mdm/profiles/com.apple.finder.yaml"
        | "mdm/profiles/com.apple.screensaver.yaml"
        | "mdm/profiles/com.apple.security.firewall.yaml" => P::ConfigurationWrite,
        "mdm/profiles/com.apple.MCX(FileVault2).yaml"
        | "mdm/profiles/com.apple.MCX(WiFi).yaml"
        | "mdm/profiles/com.apple.ManagedClient.preferences.yaml"
        | "mdm/profiles/com.apple.MCX(Accounts).yaml"
        | "mdm/profiles/com.apple.ADCertificate.managed.yaml"
        | "mdm/profiles/com.apple.AIM.account.yaml"
        | "mdm/profiles/com.apple.AssetCache.managed.yaml"
        | "mdm/profiles/com.apple.Dictionary.yaml"
        | "mdm/profiles/com.apple.DirectoryService.managed.yaml"
        | "mdm/profiles/com.apple.DiscRecording.yaml"
        | "mdm/profiles/com.apple.MCX.FileVault2.yaml"
        | "mdm/profiles/com.apple.MCX.TimeMachine.yaml"
        | "mdm/profiles/com.apple.NSExtension.yaml"
        | "mdm/profiles/com.apple.SetupAssistant.managed.yaml"
        | "mdm/profiles/com.apple.ShareKitHelper.yaml"
        | "mdm/profiles/com.apple.SoftwareUpdate.yaml"
        | "mdm/profiles/com.apple.SystemConfiguration.yaml"
        | "mdm/profiles/com.apple.TCC.configuration-profile-policy.yaml"
        | "mdm/profiles/com.apple.airplay.yaml"
        | "mdm/profiles/com.apple.airprint.yaml"
        | "mdm/profiles/com.apple.applicationaccess.new.yaml"
        | "mdm/profiles/com.apple.applicationaccess.yaml"
        | "mdm/profiles/com.apple.appstore.yaml"
        | "mdm/profiles/com.apple.asam.yaml"
        | "mdm/profiles/com.apple.associated-domains.yaml"
        | "mdm/profiles/com.apple.caldav.account.yaml"
        | "mdm/profiles/com.apple.carddav.account.yaml"
        | "mdm/profiles/com.apple.configurationprofile.identification.yaml"
        | "mdm/profiles/com.apple.dashboard.yaml"
        | "mdm/profiles/com.apple.declarations.yaml"
        | "mdm/profiles/com.apple.dnsProxy.managed.yaml"
        | "mdm/profiles/com.apple.dnsSettings.managed.yaml"
        | "mdm/profiles/com.apple.domains.yaml"
        | "mdm/profiles/com.apple.education.yaml"
        | "mdm/profiles/com.apple.ews.account.yaml"
        | "mdm/profiles/com.apple.extensiblesso(kerberos).yaml"
        | "mdm/profiles/com.apple.extensiblesso.yaml"
        | "mdm/profiles/com.apple.familycontrols.contentfilter.yaml"
        | "mdm/profiles/com.apple.familycontrols.timelimits.v2.yaml"
        | "mdm/profiles/com.apple.fileproviderd.yaml"
        | "mdm/profiles/com.apple.firstactiveethernet.managed.yaml"
        | "mdm/profiles/com.apple.firstethernet.managed.yaml"
        | "mdm/profiles/com.apple.font.yaml"
        | "mdm/profiles/com.apple.gamed.yaml"
        | "mdm/profiles/com.apple.globalethernet.managed.yaml"
        | "mdm/profiles/com.apple.ironwood.support.yaml"
        | "mdm/profiles/com.apple.jabber.account.yaml"
        | "mdm/profiles/com.apple.ldap.account.yaml"
        | "mdm/profiles/com.apple.loginitems.managed.yaml"
        | "mdm/profiles/com.apple.loginwindow.yaml"
        | "mdm/profiles/com.apple.lom.yaml"
        | "mdm/profiles/com.apple.mail.managed.yaml"
        | "mdm/profiles/com.apple.mcxMenuExtras.yaml"
        | "mdm/profiles/com.apple.mcxloginscripts.yaml"
        | "mdm/profiles/com.apple.mcxprinting.yaml"
        | "mdm/profiles/com.apple.mdm.yaml"
        | "mdm/profiles/com.apple.mobiledevice.passwordpolicy.yaml"
        | "mdm/profiles/com.apple.notificationsettings.yaml"
        | "mdm/profiles/com.apple.preference.security.yaml"
        | "mdm/profiles/com.apple.preferences.users.yaml"
        | "mdm/profiles/com.apple.profileRemovalPassword.yaml"
        | "mdm/profiles/com.apple.proxy.http.global.yaml"
        | "mdm/profiles/com.apple.relay.managed.yaml"
        | "mdm/profiles/com.apple.screensaver.user.yaml"
        | "mdm/profiles/com.apple.secondactiveethernet.managed.yaml"
        | "mdm/profiles/com.apple.secondethernet.managed.yaml"
        | "mdm/profiles/com.apple.security.FDERecoveryKeyEscrow.yaml"
        | "mdm/profiles/com.apple.security.FDERecoveryRedirect.yaml"
        | "mdm/profiles/com.apple.security.acme.yaml"
        | "mdm/profiles/com.apple.security.certificatepreference.yaml"
        | "mdm/profiles/com.apple.security.certificatetransparency.yaml"
        | "mdm/profiles/com.apple.security.identitypreference.yaml"
        | "mdm/profiles/com.apple.security.pem.yaml"
        | "mdm/profiles/com.apple.security.pkcs1.yaml"
        | "mdm/profiles/com.apple.security.pkcs12.yaml"
        | "mdm/profiles/com.apple.security.root.yaml"
        | "mdm/profiles/com.apple.security.scep.yaml"
        | "mdm/profiles/com.apple.security.smartcard.yaml"
        | "mdm/profiles/com.apple.servicemanagement.yaml"
        | "mdm/profiles/com.apple.syspolicy.kernel-extension-policy.yaml"
        | "mdm/profiles/com.apple.system-extension-policy.yaml"
        | "mdm/profiles/com.apple.system.logging.yaml"
        | "mdm/profiles/com.apple.systemmigration.yaml"
        | "mdm/profiles/com.apple.systempolicy.control.yaml"
        | "mdm/profiles/com.apple.systempolicy.managed.yaml"
        | "mdm/profiles/com.apple.systempolicy.rule.yaml"
        | "mdm/profiles/com.apple.systempreferences.yaml"
        | "mdm/profiles/com.apple.systemuiserver.yaml"
        | "mdm/profiles/com.apple.thirdactiveethernet.managed.yaml"
        | "mdm/profiles/com.apple.thirdethernet.managed.yaml"
        | "mdm/profiles/com.apple.universalaccess.yaml"
        | "mdm/profiles/com.apple.vpn.managed.applayer.yaml"
        | "mdm/profiles/com.apple.vpn.managed.appmapping.yaml"
        | "mdm/profiles/com.apple.vpn.managed.yaml"
        | "mdm/profiles/com.apple.webClip.managed.yaml"
        | "mdm/profiles/com.apple.webcontent-filter.yaml"
        | "mdm/profiles/com.apple.wifi.managed.yaml"
        | "mdm/profiles/com.apple.xsan.preferences.yaml"
        | "mdm/profiles/com.apple.xsan.yaml"
        | "mdm/profiles/loginwindow.yaml" => P::SecurityOperate,
        _ => return Err(Error::Unsupported),
    })
}
fn windows(
    request: &rss_mdm_windows_mdm::native::Request,
    out: &mut BTreeSet<P>,
) -> Result<(), Error> {
    use rss_mdm_windows_mdm::native::AuthorizationTarget;
    let resolved = request.resolve().map_err(|_| Error::Malformed)?;
    for target in resolved.authorization() {
        match target {
            AuthorizationTarget::Csp { node, operation } => windows_node(node, *operation, out)?,
            AuthorizationTarget::Mi { .. } => {
                out.insert(P::WindowsMiExecute);
            }
            AuthorizationTarget::DeclaredInterval => {
                out.insert(P::ConfigurationWrite);
            }
            AuthorizationTarget::DeclaredResult => {
                out.extend([P::InventoryCollect, P::SecurityOperate, P::Credentials]);
            }
        }
    }
    Ok(())
}
fn windows_node(
    node: &str,
    operation: rss_mdm_windows_mdm::native::Verb,
    out: &mut BTreeSet<P>,
) -> Result<(), Error> {
    use rss_mdm_windows_mdm::native::Verb;
    let read = operation == Verb::Get;
    if node.starts_with("./DevInfo") || node.starts_with("./DevDetail") {
        if read {
            out.insert(P::InventoryCollect);
            return Ok(());
        }
        return Err(Error::Unsupported);
    }
    if node == "./SyncML/DMAcc" || node.starts_with("./SyncML/DMAcc/") {
        // authorization_nodes has already rejected nodes absent from the pinned schema.
        out.insert(P::Enrollment);
        if node
            .split('/')
            .any(|segment| matches!(segment, "AAuthSecret" | "AAuthData"))
        {
            out.insert(P::Credentials);
            out.insert(P::SecurityOperate);
        }
        return Ok(());
    }
    let path = node
        .split("/Vendor/MSFT/")
        .nth(1)
        .ok_or(Error::Unsupported)?;
    let mut parts = path.split('/');
    let family = parts.next().ok_or(Error::Unsupported)?;
    let area = if family == "Policy" {
        match (parts.next(), parts.next()) {
            (Some("Config" | "Result"), Some(area)) => area,
            _ => return Err(Error::Unsupported),
        }
    } else {
        family
    };
    let permission = match area {
        "RemoteWipe" if !read => P::DeviceWipe,
        "EnterpriseDesktopAppManagement" | "EnterpriseModernAppManagement" if !read => {
            P::SoftwareDeploy
        }
        "CertificateStore"
        | "ClientCertificateInstall"
        | "PassportForWork"
        | "RootCATrustedCertificates"
        | "BitLocker"
        | "Defender"
        | "DeviceGuard"
        | "LAPS"
        | "HealthAttestation"
        | "PDE"
        | "ApplicationControl"
        | "AppLocker"
        | "WindowsDefenderApplicationGuard"
        | "Authentication"
        | "Security"
        | "SecurityOptions"
        | "LocalPoliciesSecurityOptions"
        | "UserRights"
        | "CredentialsUI"
        | "ADMX_CredSsp"
        | "ADMX_CredentialProviders" => P::SecurityOperate,
        "Accounts" | "LocalUsersAndGroups" if !read => P::AccountWrite,
        "Update" if !read => P::DeviceUpdate,
        "DiagnosticLog" => P::DeviceDiagnostics,
        "DMClient" => P::Enrollment,
        "Reboot" | "RemoteLock" | "RemoteRemediation" if !read => P::DeviceControl,
        "DeclaredConfiguration" => return Err(Error::Unsupported),
        _ if family == "Policy" && security_policy_area(area) => P::SecurityOperate,
        _ if family == "Policy"
            && !configuration_policy_area(area)
            && !matches!(area, "Update" | "Accounts" | "LocalUsersAndGroups") =>
        {
            return Err(Error::Unsupported);
        }
        _ if read => P::InventoryCollect,
        _ if operation == Verb::Exec => return Err(Error::Unsupported),
        _ if family == "Policy" && configuration_policy_area(area) => P::ConfigurationWrite,
        _ if family == "Policy" && security_policy_area(area) => P::SecurityOperate,
        _ if family != "Policy" && configuration_family(family) => P::ConfigurationWrite,
        _ => return Err(Error::Unsupported),
    };
    out.insert(permission);
    if path.split('/').any(|segment| {
        matches!(
            segment,
            "WlanXml"
                | "ProfileXML"
                | "Password"
                | "PasswordValue"
                | "PFXCertBlob"
                | "PFXCertPassword"
                | "PrivateKey"
                | "Secret"
                | "RecoveryKey"
        )
    }) {
        out.insert(P::Credentials);
        out.insert(P::SecurityOperate);
    }
    Ok(())
}
fn configuration_family(family: &str) -> bool {
    matches!(
        family,
        "ActiveSync"
            | "AssignedAccess"
            | "CloudDesktop"
            | "DeviceManageability"
            | "DevicePreparation"
            | "DeviceStatus"
            | "DnsClient"
            | "EMAIL2"
            | "Firewall"
            | "LanguagePackManagement"
            | "MultiSIM"
            | "NetworkProxy"
            | "NetworkQoSPolicy"
            | "NodeCache"
            | "Office"
            | "Personalization"
            | "PrinterProvisioning"
            | "SecureAssessment"
            | "SharedPC"
            | "VPNv2"
            | "WiFi"
            | "WindowsBackupAndRestore"
            | "WindowsLicensing"
            | "WiredNetwork"
            | "WirelessNetworkPreference"
            | "eUICCs"
    )
}
fn apple_command(name: &str) -> Result<P, Error> {
    Ok(match name {
        "EraseDevice" => P::DeviceWipe,
        "DeviceLock"
        | "RestartDevice"
        | "ShutDownDevice"
        | "LOMDeviceRequest"
        | "LOMSetupRequest"
        | "RequestMirroring"
        | "StopMirroring"
        | "EnableRemoteDesktop"
        | "DisableRemoteDesktop" => P::DeviceControl,
        "InstallApplication"
        | "InstallEnterpriseApplication"
        | "RemoveApplication"
        | "ManagedApplicationConfiguration" => P::SoftwareDeploy,
        "ScheduleOSUpdate" | "ScheduleOSUpdateScan" => P::DeviceUpdate,
        "AccountConfiguration" | "DeleteUser" | "UnlockUserAccount" | "SetAutoAdminPassword" => {
            P::AccountWrite
        }
        "ActivationLockBypassCode"
        | "ClearActivationLockBypassCode"
        | "SetFirmwarePassword"
        | "VerifyFirmwarePassword"
        | "SetRecoveryLock"
        | "VerifyRecoveryLock"
        | "RotateFileVaultKey" => P::SecurityOperate,
        "CancelEnhancedLogCollection" | "TriggerEnhancedLogCollection" => P::DeviceDiagnostics,
        "DeviceConfigured" | "InviteToProgram" => P::Enrollment,
        "InstallProvisioningProfile" | "RemoveProvisioningProfile" => P::Credentials,
        "Settings" => P::ConfigurationWrite,
        "DeviceInformation"
        | "InstalledApplicationList"
        | "ManagedApplicationList"
        | "ManagedApplicationFeedback"
        | "ProfileList"
        | "ProvisioningProfileList"
        | "CertificateList"
        | "SecurityInfo"
        | "ContentCachingInformation"
        | "ActiveNSExtensions"
        | "NSExtensionMappings"
        | "UserList"
        | "AvailableOSUpdates"
        | "OSUpdateStatus" => P::InventoryCollect,
        // These commands enter through native ownership-aware lifecycle inputs.
        "InstallProfile" | "RemoveProfile" | "DeclarativeManagement" => {
            return Err(Error::Malformed);
        }
        _ => return Err(Error::Unsupported),
    })
}

// Product authorization for the pinned Policy areas. New source areas require explicit review.
fn configuration_policy_area(area: &str) -> bool {
    matches!(
        area,
        "ApplicationDefaults"
            | "Browser"
            | "Connectivity"
            | "Display"
            | "Education"
            | "Experience"
            | "FileExplorer"
            | "Printers"
            | "Privacy"
            | "Search"
            | "Start"
            | "Storage"
            | "System"
            | "TextInput"
            | "TimeLanguageSettings"
            | "WindowsInkWorkspace"
            | "WirelessDisplay"
    )
}
fn security_policy_area(area: &str) -> bool {
    matches!(
        area,
        "*" | "ADMX_ActiveXInstallService"
            | "ADMX_AddRemovePrograms"
            | "ADMX_AdmPwd"
            | "ADMX_AppCompat"
            | "ADMX_AppXRuntime"
            | "ADMX_AppxPackageManager"
            | "ADMX_AttachmentManager"
            | "ADMX_AuditSettings"
            | "ADMX_Bits"
            | "ADMX_COM"
            | "ADMX_CipherSuiteOrder"
            | "ADMX_ControlPanel"
            | "ADMX_ControlPanelDisplay"
            | "ADMX_Cpls"
            | "ADMX_CredSsp"
            | "ADMX_CredUI"
            | "ADMX_CredentialProviders"
            | "ADMX_CtrlAltDel"
            | "ADMX_DCOM"
            | "ADMX_DFS"
            | "ADMX_DWM"
            | "ADMX_DataCollection"
            | "ADMX_Desktop"
            | "ADMX_DeviceCompat"
            | "ADMX_DeviceGuard"
            | "ADMX_DeviceInstallation"
            | "ADMX_DeviceSetup"
            | "ADMX_DigitalLocker"
            | "ADMX_DiskDiagnostic"
            | "ADMX_DiskNVCache"
            | "ADMX_DiskQuota"
            | "ADMX_DistributedLinkTracking"
            | "ADMX_DnsClient"
            | "ADMX_EAIME"
            | "ADMX_EncryptFilesonMove"
            | "ADMX_EnhancedStorage"
            | "ADMX_ErrorReporting"
            | "ADMX_EventForwarding"
            | "ADMX_EventLog"
            | "ADMX_EventLogging"
            | "ADMX_EventViewer"
            | "ADMX_Explorer"
            | "ADMX_ExternalBoot"
            | "ADMX_FileRecovery"
            | "ADMX_FileRevocation"
            | "ADMX_FileServerVSSProvider"
            | "ADMX_FileSys"
            | "ADMX_FolderRedirection"
            | "ADMX_FramePanes"
            | "ADMX_Globalization"
            | "ADMX_GroupPolicy"
            | "ADMX_Help"
            | "ADMX_HelpAndSupport"
            | "ADMX_ICM"
            | "ADMX_IIS"
            | "ADMX_Kerberos"
            | "ADMX_LanmanServer"
            | "ADMX_LanmanWorkstation"
            | "ADMX_LeakDiagnostic"
            | "ADMX_LinkLayerTopologyDiscovery"
            | "ADMX_LocationProviderAdm"
            | "ADMX_Logon"
            | "ADMX_MMC"
            | "ADMX_MMCSnapins"
            | "ADMX_MSAPolicy"
            | "ADMX_MSDT"
            | "ADMX_MSI"
            | "ADMX_MSS-legacy"
            | "ADMX_MicrosoftDefenderAntivirus"
            | "ADMX_MobilePCMobilityCenter"
            | "ADMX_MobilePCPresentationSettings"
            | "ADMX_MsiFileRecovery"
            | "ADMX_NCSI"
            | "ADMX_Netlogon"
            | "ADMX_NetworkConnections"
            | "ADMX_OfflineFiles"
            | "ADMX_PeerToPeerCaching"
            | "ADMX_PenTraining"
            | "ADMX_PerformanceDiagnostics"
            | "ADMX_Power"
            | "ADMX_PowerShellExecutionPolicy"
            | "ADMX_PreviousVersions"
            | "ADMX_Printing"
            | "ADMX_Printing2"
            | "ADMX_Programs"
            | "ADMX_PushToInstall"
            | "ADMX_QOS"
            | "ADMX_RPC"
            | "ADMX_Radar"
            | "ADMX_Reliability"
            | "ADMX_RemoteAssistance"
            | "ADMX_RemovableStorage"
            | "ADMX_Scripts"
            | "ADMX_Securitycenter"
            | "ADMX_Sensors"
            | "ADMX_ServerManager"
            | "ADMX_Servicing"
            | "ADMX_SettingSync"
            | "ADMX_SharedFolders"
            | "ADMX_Sharing"
            | "ADMX_ShellCommandPromptRegEditTools"
            | "ADMX_Smartcard"
            | "ADMX_Snmp"
            | "ADMX_SoundRec"
            | "ADMX_StartMenu"
            | "ADMX_SystemRestore"
            | "ADMX_TPM"
            | "ADMX_TabletPCInputPanel"
            | "ADMX_TabletShell"
            | "ADMX_Taskbar"
            | "ADMX_TerminalServer"
            | "ADMX_Thumbnails"
            | "ADMX_TouchInput"
            | "ADMX_UserExperienceVirtualization"
            | "ADMX_UserProfiles"
            | "ADMX_W32Time"
            | "ADMX_WCM"
            | "ADMX_WDI"
            | "ADMX_WPN"
            | "ADMX_WinCal"
            | "ADMX_WinInit"
            | "ADMX_WinLogon"
            | "ADMX_WindowsColorSystem"
            | "ADMX_WindowsConnectNow"
            | "ADMX_WindowsExplorer"
            | "ADMX_WindowsMediaDRM"
            | "ADMX_WindowsMediaPlayer"
            | "ADMX_WindowsRemoteManagement"
            | "ADMX_WindowsStore"
            | "ADMX_Winsrv"
            | "ADMX_WordWheel"
            | "ADMX_WorkFoldersClient"
            | "ADMX_fthsvc"
            | "ADMX_hotspotauth"
            | "ADMX_iSCSI"
            | "ADMX_kdc"
            | "ADMX_msched"
            | "ADMX_nca"
            | "ADMX_pca"
            | "ADMX_sam"
            | "ADMX_sdiageng"
            | "ADMX_sdiagschd"
            | "ADMX_srmfci"
            | "ADMX_tcpip"
            | "ADMX_wlansvc"
            | "AboveLock"
            | "ActiveXControls"
            | "AppDeviceInventory"
            | "AppRuntime"
            | "AppVirtualization"
            | "ApplicationManagement"
            | "AttachmentManager"
            | "Audit"
            | "Authentication"
            | "Autoplay"
            | "BITS"
            | "Bitlocker"
            | "Bluetooth"
            | "Camera"
            | "Cellular"
            | "CloudDesktop"
            | "ControlPolicyConflict"
            | "CredentialProviders"
            | "CredentialsDelegation"
            | "CredentialsUI"
            | "Cryptography"
            | "DataProtection"
            | "DataUsage"
            | "Defender"
            | "DeliveryOptimization"
            | "Desktop"
            | "DesktopAppInstaller"
            | "DeviceGuard"
            | "DeviceHealthMonitoring"
            | "DeviceInstallation"
            | "DeviceLock"
            | "DmaGuard"
            | "Eap"
            | "EnterpriseCloudPrint"
            | "ErrorReporting"
            | "EventLogService"
            | "ExploitGuard"
            | "FederatedAuthentication"
            | "FileSystem"
            | "Games"
            | "Handwriting"
            | "HumanPresence"
            | "InternetExplorer"
            | "Kerberos"
            | "KioskBrowser"
            | "LanmanServer"
            | "LanmanWorkstation"
            | "Licensing"
            | "LocalPoliciesSecurityOptions"
            | "LocalSecurityAuthority"
            | "LockDown"
            | "MSSLegacy"
            | "MSSecurityGuide"
            | "Maps"
            | "MemoryDump"
            | "Messaging"
            | "MixedReality"
            | "Multitasking"
            | "NetworkIsolation"
            | "NetworkListManager"
            | "NewsAndInterests"
            | "Notifications"
            | "Power"
            | "RemoteAssistance"
            | "RemoteDesktop"
            | "RemoteDesktopServices"
            | "RemoteManagement"
            | "RemoteProcedureCall"
            | "RemoteShell"
            | "RestrictedGroups"
            | "SecureBoot"
            | "Security"
            | "ServiceControlManager"
            | "Settings"
            | "SettingsSync"
            | "SmartScreen"
            | "Speech"
            | "Stickers"
            | "Sudo"
            | "SystemServices"
            | "TaskManager"
            | "TaskScheduler"
            | "TenantDefinedTelemetry"
            | "TenantRestrictions"
            | "Troubleshooting"
            | "UserRights"
            | "VirtualizationBasedTechnology"
            | "WebThreatDefense"
            | "Wifi"
            | "WindowsAI"
            | "WindowsAutopilot"
            | "WindowsConnectionManager"
            | "WindowsDefenderSecurityCenter"
            | "WindowsLogon"
            | "WindowsPowerShell"
            | "WindowsSandbox"
    )
}

#[cfg(test)]
mod windows_tests {
    use super::*;
    use rss_mdm_windows_mdm::native::Verb;
    #[test]
    fn apple_profile_security_is_explicit_and_unknown_schema_is_rejected() {
        for schema in [
            "com.apple.MCX.FileVault2.yaml",
            "com.apple.MCX(FileVault2).yaml",
            "com.apple.TCC.configuration-profile-policy.yaml",
            "com.apple.mobiledevice.passwordpolicy.yaml",
            "com.apple.security.pkcs1.yaml",
            "com.apple.ManagedClient.preferences.yaml",
        ] {
            assert_eq!(
                apple_profile(&format!("mdm/profiles/{schema}")).unwrap(),
                P::SecurityOperate
            );
        }
        assert_eq!(
            apple_profile("mdm/profiles/com.apple.security.firewall.yaml").unwrap(),
            P::ConfigurationWrite
        );
        assert!(apple_profile("mdm/profiles/new-unknown-security.yaml").is_err());
    }
    #[test]
    fn nested_policy_operations_keep_their_real_permissions() {
        let mut permissions = BTreeSet::new();
        windows_node(
            "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate",
            Verb::Replace,
            &mut permissions,
        )
        .unwrap();
        windows_node(
            "./Device/Vendor/MSFT/Policy/Result/Defender/AllowRealTimeMonitoring",
            Verb::Get,
            &mut permissions,
        )
        .unwrap();
        assert!(permissions.contains(&P::DeviceUpdate));
        assert!(permissions.contains(&P::SecurityOperate));
        assert!(!permissions.contains(&P::ConfigurationWrite));
    }
    #[test]
    fn dmacc_requires_enrollment_and_secrets_require_separate_authority() {
        let mut permissions = BTreeSet::new();
        windows_node("./SyncML/DMAcc/*/Name", Verb::Replace, &mut permissions).unwrap();
        assert_eq!(permissions, BTreeSet::from([P::Enrollment]));
        windows_node(
            "./SyncML/DMAcc/*/AppAuth/*/AAuthSecret",
            Verb::Replace,
            &mut permissions,
        )
        .unwrap();
        assert_eq!(
            permissions,
            BTreeSet::from([P::Enrollment, P::Credentials, P::SecurityOperate])
        );
        let unknown = rss_mdm_windows_mdm::native::Request::Node {
            node: "./SyncML/DMAcc/*/Invented".into(),
            instance: vec!["account".into()],
            operation: Verb::Replace,
            value: Some(rss_mdm_windows_mdm::native::Value::Text("x".into())),
        };
        assert!(windows(&unknown, &mut permissions).is_err());
    }
    #[test]
    fn secrets_require_credentials_and_unknown_mutations_fail_closed() {
        let mut permissions = BTreeSet::new();
        windows_node(
            "./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/*/PFXCertPassword",
            Verb::Replace,
            &mut permissions,
        )
        .unwrap();
        assert!(permissions.contains(&P::Credentials));
        assert!(
            windows_node(
                "./Device/Vendor/MSFT/Invented/Value",
                Verb::Replace,
                &mut permissions
            )
            .is_err()
        );
        assert!(
            windows_node(
                "./Device/Vendor/MSFT/DeclaredConfiguration/Host",
                Verb::Get,
                &mut permissions
            )
            .is_err()
        );
    }
}
