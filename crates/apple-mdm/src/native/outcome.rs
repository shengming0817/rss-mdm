//! Pure interpretation of native execution evidence; product authority stays with the caller.
//! ref: apple/device-management mdm/commands/{system.update.status,application.managed.list,device.restart}.yaml@09f249a06e7e3289930bf6d05f38fb562f748ebf.
use super::{Error, Target, input::CommandInput};
use crate::{applicability::Context, protocol::Status};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Query,
    Application,
    Security,
    Account,
    Profile,
    Control,
    Update,
    Settings,
    Diagnostic,
}
/// Every accepted command has an explicit behavior owner. DDM is owned separately.
pub fn family(name: &str) -> Result<Family, Error> {
    use Family::*;
    Ok(match name {
        "ActiveNSExtensions"
        | "NSExtensionMappings"
        | "InstalledApplicationList"
        | "ManagedApplicationList"
        | "ManagedApplicationFeedback"
        | "CertificateList"
        | "ActivationLockBypassCode"
        | "ContentCachingInformation"
        | "DeviceInformation"
        | "SecurityInfo"
        | "ProfileList"
        | "ProvisioningProfileList"
        | "UserList"
        | "AvailableOSUpdates"
        | "OSUpdateStatus" => Query,
        "InstallEnterpriseApplication"
        | "InstallApplication"
        | "InviteToProgram"
        | "RemoveApplication"
        | "ManagedApplicationConfiguration"
        | "InstallMedia" => Application,
        "ClearActivationLockBypassCode"
        | "LOMDeviceRequest"
        | "LOMSetupRequest"
        | "SetFirmwarePassword"
        | "VerifyFirmwarePassword"
        | "SetRecoveryLock"
        | "VerifyRecoveryLock"
        | "RotateFileVaultKey" => Security,
        "AccountConfiguration" | "SetAutoAdminPassword" | "DeleteUser" | "UnlockUserAccount" => {
            Account
        }
        "InstallProfile"
        | "InstallProvisioningProfile"
        | "RemoveProvisioningProfile"
        | "RemoveProfile" => Profile,
        "DeviceConfigured"
        | "EraseDevice"
        | "DeviceLock"
        | "RestartDevice"
        | "ShutDownDevice"
        | "RequestMirroring"
        | "StopMirroring"
        | "DisableRemoteDesktop"
        | "EnableRemoteDesktop" => Control,
        "ScheduleOSUpdateScan" | "ScheduleOSUpdate" => Update,
        "Settings" => Settings,
        "CancelEnhancedLogCollection" | "TriggerEnhancedLogCollection" => Diagnostic,
        "DeclarativeManagement" | "RunScript" => return Err(Error::Unsupported),
        _ => return Err(Error::UnknownSchema),
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    QueryResult,
    Acknowledged,
    Deferred,
    PendingRestart,
    InProgress,
    Rejected,
    Unknown,
}
impl Outcome {
    pub fn completes_query(self) -> bool {
        self == Self::QueryResult
    }
}
/// These facts never authorize another mutation or claim settings/compliance effects.
pub fn interpret(
    command: &CommandInput,
    response: &Dictionary,
    status: Status,
    target: &Target<'_>,
) -> Result<Outcome, Error> {
    let compiled = command.compile(target)?;
    let family = family(&command.request_type)?;
    if status == Status::NotNow {
        return Ok(Outcome::Deferred);
    }
    if status == Status::Error {
        return Ok(Outcome::Rejected);
    }
    if status != Status::Acknowledged {
        return Err(Error::Constraint);
    }
    let mut fields = response.clone();
    for key in [
        "Status",
        "CommandUUID",
        "UDID",
        "UserID",
        "UserLongName",
        "UserShortName",
        "EnrollmentID",
        "EnrollmentUserID",
        "AuthToken",
    ] {
        fields.remove(key);
    }
    compiled.validate_response(&fields, target)?;
    if command.request_type == "LOMDeviceRequest" {
        let items = fields
            .get("ResponseList")
            .and_then(Value::as_array)
            .ok_or(Error::Field)?;
        let mut unknown = items.is_empty();
        for item in items {
            let item = item.as_dictionary().ok_or(Error::Field)?;
            if item.get("DeviceRequestSuccess").and_then(Value::as_boolean) == Some(false)
                || item.contains_key("DeviceRequestReturnError")
            {
                return Ok(Outcome::Rejected);
            }
            unknown |= item.get("DeviceRequestSuccess").and_then(Value::as_boolean) != Some(true);
        }
        return Ok(if unknown {
            Outcome::Unknown
        } else {
            Outcome::Acknowledged
        });
    }
    if command.request_type == "ManagedApplicationList" {
        let apps = fields
            .get("ManagedApplicationList")
            .and_then(Value::as_dictionary)
            .ok_or(Error::Field)?;
        let mut outcome = Outcome::QueryResult;
        for value in apps.values() {
            let status = value
                .as_dictionary()
                .and_then(|d| d.get("Status"))
                .and_then(Value::as_string)
                .ok_or(Error::Field)?;
            if matches!(
                status,
                "UserRejected" | "UpdateRejected" | "ManagementRejected" | "Failed"
            ) {
                outcome = merge(outcome, Outcome::Rejected);
            }
            if status == "Unknown" {
                outcome = merge(outcome, Outcome::Unknown);
            }
            if matches!(
                status,
                "Queued"
                    | "Installing"
                    | "Updating"
                    | "Removing"
                    | "Prompting"
                    | "PromptingForLogin"
                    | "ValidatingPurchase"
                    | "NeedsRedemption"
                    | "Redeeming"
                    | "PromptingForUpdate"
                    | "PromptingForUpdateLogin"
                    | "PromptingForManagement"
                    | "ValidatingUpdate"
            ) {
                outcome = merge(outcome, Outcome::InProgress);
            }
        }
        return Ok(outcome);
    }
    if command.request_type == "ScheduleOSUpdate" {
        let items = fields
            .get("UpdateResults")
            .and_then(Value::as_array)
            .ok_or(Error::Field)?;
        if items.is_empty() {
            return Ok(Outcome::Unknown);
        }
        let mut outcome = Outcome::InProgress;
        for value in items {
            let item = value.as_dictionary().ok_or(Error::Field)?;
            if item.get("InstallAction").and_then(Value::as_string) == Some("Error")
                || item.contains_key("ErrorChain")
                || item
                    .get("Status")
                    .and_then(Value::as_string)
                    .is_some_and(|status| {
                        status.contains("Failed")
                            || status.contains("Insufficient")
                            || status == "DownloadRequiresComputer"
                    })
            {
                outcome = merge(outcome, Outcome::Rejected);
            }
            if item.get("InstallAction").and_then(Value::as_string) == Some("InstallLater") {
                outcome = merge(outcome, Outcome::Deferred);
            }
        }
        return Ok(outcome);
    }
    if command.request_type == "OSUpdateStatus" {
        let items = fields
            .get("OSUpdateStatus")
            .and_then(Value::as_array)
            .ok_or(Error::Field)?;
        let mut outcome = Outcome::QueryResult;
        for value in items {
            let item = value.as_dictionary().ok_or(Error::Field)?;
            let result = match item.get("Status").and_then(Value::as_string) {
                Some("Failed") => Outcome::Rejected,
                Some("Installing" | "Downloading" | "Idle")
                    if item.contains_key("NextScheduledInstall") =>
                {
                    Outcome::Deferred
                }
                Some("Installing" | "Downloading" | "Idle") => Outcome::InProgress,
                _ => Outcome::Unknown,
            };
            outcome = merge(outcome, result);
        }
        return Ok(outcome);
    }
    if matches!(
        command.request_type.as_str(),
        "VerifyRecoveryLock" | "VerifyFirmwarePassword"
    ) {
        let result = if command.request_type == "VerifyFirmwarePassword" {
            fields
                .get("VerifyFirmwarePassword")
                .and_then(Value::as_dictionary)
                .ok_or(Error::Field)?
        } else {
            &fields
        };
        return Ok(
            match result.get("PasswordVerified").and_then(Value::as_boolean) {
                Some(true) => Outcome::Acknowledged,
                Some(false) => Outcome::Rejected,
                None => Outcome::Unknown,
            },
        );
    }
    if command.request_type == "SetFirmwarePassword" {
        return Ok(
            if fields
                .get("SetFirmwarePassword")
                .and_then(Value::as_dictionary)
                .and_then(|d| d.get("PasswordChanged"))
                .and_then(Value::as_boolean)
                == Some(true)
            {
                Outcome::PendingRestart
            } else {
                Outcome::Unknown
            },
        );
    }
    if command.request_type == "InviteToProgram"
        && fields.get("InvitationResult").and_then(Value::as_string) != Some("Acknowledged")
    {
        return Ok(Outcome::Rejected);
    }
    if command.request_type == "Settings" {
        return Ok(
            match fields
                .get("Settings")
                .and_then(Value::as_dictionary)
                .and_then(|item| item.get("Status"))
                .and_then(Value::as_string)
            {
                Some("Error" | "CommandFormatError") => Outcome::Rejected,
                Some("NotNow") => Outcome::Deferred,
                Some("Acknowledged") => Outcome::Acknowledged,
                _ => Outcome::Unknown,
            },
        );
    }
    if matches!(
        command.request_type.as_str(),
        "RestartDevice" | "ShutDownDevice"
    ) {
        return Ok(Outcome::PendingRestart);
    }
    if command.request_type == "EraseDevice" {
        return Ok(Outcome::Unknown);
    }
    Ok(if family == Family::Query {
        Outcome::QueryResult
    } else {
        Outcome::Acknowledged
    })
}
// Complete collections have an order-independent, conservative summary. Raw receipts
// remain authoritative; a rejected item never claims other items had no side effects.
fn merge(left: Outcome, right: Outcome) -> Outcome {
    let rank = |value| match value {
        Outcome::Rejected => 5,
        Outcome::Unknown => 4,
        Outcome::Deferred => 3,
        Outcome::InProgress => 2,
        _ => 1,
    };
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}
/// Independent bounded reads reuse the existing attempt stream; absence never authorizes mutation replay.
pub fn follow_up(command: &CommandInput) -> Result<Option<CommandInput>, Error> {
    if command.request_type == "ScheduleOSUpdate" {
        return Ok(Some(CommandInput {
            request_type: "OSUpdateStatus".into(),
            fields: Default::default(),
        }));
    }
    crate::software::observation(command).map_err(|_| Error::Constraint)
}
pub(super) fn prerequisites(
    name: &str,
    fields: &Dictionary,
    context: &Context,
) -> Result<(), Error> {
    if matches!(name, "SetRecoveryLock" | "VerifyRecoveryLock")
        && context.apple_silicon != Some(true)
    {
        return Err(Error::Unsupported);
    }
    if matches!(name, "SetFirmwarePassword" | "VerifyFirmwarePassword")
        && context.apple_silicon != Some(false)
    {
        return Err(Error::Unsupported);
    }
    if name == "ScheduleOSUpdate"
        && let Some(items) = fields.get("Updates").and_then(Value::as_array)
    {
        for value in items {
            let item = value.as_dictionary().ok_or(Error::Field)?;
            if item.contains_key("MaxUserDeferrals")
                && item.get("InstallAction").and_then(Value::as_string) != Some("InstallLater")
            {
                return Err(Error::Constraint);
            }
            if !item.contains_key("ProductKey") && !item.contains_key("ProductVersion") {
                return Err(Error::Constraint);
            }
        }
    }
    Ok(())
}
