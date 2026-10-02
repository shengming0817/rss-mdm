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
fn windows(
    request: &rss_mdm_windows_mdm::native::Request,
    out: &mut BTreeSet<P>,
) -> Result<(), Error> {
    use rss_mdm_windows_mdm::native::{Request, Verb};
    match request {
        Request::Atomic { operations } | Request::Sequence { operations } => {
            for operation in operations {
                windows(operation, out)?;
            }
        }
        Request::Node {
            node, operation, ..
        } => {
            let read = *operation == Verb::Get;
            let family = node
                .split("/Vendor/MSFT/")
                .nth(1)
                .and_then(|p| p.split('/').next());
            let permission = match family {
                Some("RemoteWipe") if !read => P::DeviceWipe,
                Some("EnterpriseDesktopAppManagement" | "EnterpriseModernAppManagement")
                    if !read =>
                {
                    P::SoftwareDeploy
                }
                Some(
                    "CertificateStore"
                    | "ClientCertificateInstall"
                    | "PassportForWork"
                    | "RootCATrustedCertificates",
                ) => P::SecurityOperate,
                Some("Accounts" | "LocalUsersAndGroups") if !read => P::AccountWrite,
                Some("Update") if !read => P::DeviceUpdate,
                Some("DiagnosticLog" | "DiagnosticArchive" | "DiagnosticData") => {
                    P::DeviceDiagnostics
                }
                Some("DMClient" | "Enrollments") if !read => P::Enrollment,
                Some("Reboot" | "RemoteFind") if !read => P::DeviceControl,
                Some("BitLocker" | "Defender" | "DeviceGuard" | "LAPS") => P::SecurityOperate,
                _ if read => P::InventoryCollect,
                _ if *operation == Verb::Exec => return Err(Error::Unsupported),
                _ => P::ConfigurationWrite,
            };
            out.insert(permission);
        }
    }
    Ok(())
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
