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
                        if (payload.schema.contains("security.")
                            && !payload.schema.ends_with("com.apple.security.firewall.yaml"))
                            || payload.schema.contains("scep")
                            || payload.schema.contains("acme")
                        {
                            permissions.insert(P::SecurityOperate);
                        }
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
fn windows(request: &rss_mdm_windows_mdm::native::Request, out: &mut BTreeSet<P>) -> Result<(), Error> {
    for (node, operation) in request.authorization_nodes().map_err(|_| Error::Malformed)? {
        windows_node(&node, operation, out)?;
    }
    Ok(())
}
fn windows_node(node: &str, operation: rss_mdm_windows_mdm::native::Verb, out: &mut BTreeSet<P>) -> Result<(), Error> {
    use rss_mdm_windows_mdm::native::Verb;
    let read = operation == Verb::Get;
    if node.starts_with("./DevInfo") || node.starts_with("./DevDetail") {
        if read { out.insert(P::InventoryCollect); return Ok(()); }
        return Err(Error::Unsupported);
    }
    let path = node.split("/Vendor/MSFT/").nth(1).ok_or(Error::Unsupported)?;
    let mut parts = path.split('/');
    let family = parts.next().ok_or(Error::Unsupported)?;
    let area = if family == "Policy" {
        match (parts.next(), parts.next()) {
            (Some("Config" | "Result"), Some(area)) => area,
            _ => return Err(Error::Unsupported),
        }
    } else { family };
    let permission = match area {
        "RemoteWipe" if !read => P::DeviceWipe,
        "EnterpriseDesktopAppManagement" | "EnterpriseModernAppManagement" if !read => P::SoftwareDeploy,
        "CertificateStore" | "ClientCertificateInstall" | "PassportForWork" | "RootCATrustedCertificates"
        | "BitLocker" | "Defender" | "DeviceGuard" | "LAPS" | "HealthAttestation" | "PDE"
        | "ApplicationControl" | "AppLocker" | "WindowsDefenderApplicationGuard"
        | "Authentication" | "Security" | "SecurityOptions" | "LocalPoliciesSecurityOptions"
        | "UserRights" | "CredentialsUI" | "ADMX_CredSsp" | "ADMX_CredentialProviders" => P::SecurityOperate,
        "Accounts" | "LocalUsersAndGroups" if !read => P::AccountWrite,
        "Update" if !read => P::DeviceUpdate,
        "DiagnosticLog" => P::DeviceDiagnostics,
        "DMClient" => P::Enrollment,
        "Reboot" | "RemoteLock" | "RemoteRemediation" if !read => P::DeviceControl,
        "DeclaredConfiguration" => return Err(Error::Unsupported),
        _ if read => P::InventoryCollect,
        _ if operation == Verb::Exec => return Err(Error::Unsupported),
        _ if family == "Policy" || configuration_family(family) => P::ConfigurationWrite,
        _ => return Err(Error::Unsupported),
    };
    out.insert(permission);
    if path.split('/').any(|segment| matches!(segment, "Password" | "PasswordValue" | "PFXCertBlob" | "PFXCertPassword" | "PrivateKey" | "Secret" | "RecoveryKey")) {
        out.insert(P::Credentials);
        out.insert(P::SecurityOperate);
    }
    Ok(())
}
fn configuration_family(family: &str) -> bool {
    matches!(family,
        "ActiveSync" | "AssignedAccess" | "CloudDesktop" | "DeviceManageability"
        | "DevicePreparation" | "DeviceStatus" | "DnsClient" | "EMAIL2" | "Firewall"
        | "LanguagePackManagement" | "MultiSIM" | "NetworkProxy" | "NetworkQoSPolicy"
        | "NodeCache" | "Office" | "Personalization" | "PrinterProvisioning" | "SecureAssessment"
        | "SharedPC" | "VPNv2" | "WiFi" | "WindowsBackupAndRestore" | "WindowsLicensing"
        | "WiredNetwork" | "WirelessNetworkPreference" | "eUICCs")
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

#[cfg(test)]
mod windows_tests {
    use super::*;
    use rss_mdm_windows_mdm::native::Verb;
    #[test]
    fn nested_policy_operations_keep_their_real_permissions() {
        let mut permissions = BTreeSet::new();
        windows_node("./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate", Verb::Replace, &mut permissions).unwrap();
        windows_node("./Device/Vendor/MSFT/Policy/Result/Defender/AllowRealTimeMonitoring", Verb::Get, &mut permissions).unwrap();
        assert!(permissions.contains(&P::DeviceUpdate));
        assert!(permissions.contains(&P::SecurityOperate));
        assert!(!permissions.contains(&P::ConfigurationWrite));
    }
    #[test]
    fn secrets_require_credentials_and_unknown_mutations_fail_closed() {
        let mut permissions = BTreeSet::new();
        windows_node("./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/*/PFXCertPassword", Verb::Replace, &mut permissions).unwrap();
        assert!(permissions.contains(&P::Credentials));
        assert!(windows_node("./Device/Vendor/MSFT/Invented/Value", Verb::Replace, &mut permissions).is_err());
        assert!(windows_node("./Device/Vendor/MSFT/DeclaredConfiguration/Host", Verb::Get, &mut permissions).is_err());
    }
}
