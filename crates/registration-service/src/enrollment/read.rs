//! Current, secret-free control-plane projections; write receipts remain immutable.
use super::*;
use crate::{authorization::context::EnrollmentPermission, database::db};
use sqlx::Row;

/// Current lifecycle, never inferred from downloading or opening system settings.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Serialize, serde::Deserialize, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Bound,
    Cancelled,
    Expired,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    Observed,
    Unknown,
    NotApplicable,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Diagnostic {
    AwaitingSystemConfirmation,
    AwaitingCertificate,
    AwaitingFirstCheckIn,
    AwaitingDeviceToken,
    ReauthenticationRequired,
    Expired,
    Cancelled,
    Revoked,
    CredentialUnavailable,
    ChannelUnavailable,
    Ready,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(
    tag = "platform",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum Instructions {
    WindowsEntra {
        discovery_url: String,
        windows_profile: WindowsProfile,
        enrollment_method: &'static str,
    },
    Windows {
        server: String,
        discovery_url: String,
        username: String,
        windows_profile: WindowsProfile,
        requires_local_administrator: bool,
    },
    Macos {
        profile_url: String,
        enrollment_method: &'static str,
    },
    MacosAccount {
        managed_account: String,
        enrollment_method: &'static str,
    },
    MacosAde {
        enrollment_method: &'static str,
    },
    Unavailable,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub profile_prepared: Observation,
    pub certificate_issued: bool,
    pub first_authenticated_check_in: bool,
    pub system_confirmation: Observation,
    pub management_ready: bool,
    pub diagnostic: Diagnostic,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    enrollment_id: Uuid,
    status: State,
    expires_at: i64,
    device_id: String,
    source: ReportSource,
    instructions: Instructions,
    progress: Progress,
}
/// Trusted, tenant-limited coordinates read by the lifecycle owner; never a wire input.
pub struct Context {
    pub device: String,
    pub tenant: String,
    pub enrollment: Uuid,
    pub source: ReportSource,
    pub authorization_version: i64,
    pub account_driven: bool,
    pub organization_driven: bool,
    pub windows_profile: Option<WindowsProfile>,
    pub registration: Option<RegistrationContext>,
    pub now: i64,
}
pub struct RegistrationContext {
    pub device: String,
    pub state: RegistrationState,
    pub first_authenticated_at: Option<i64>,
    pub source_enabled: bool,
}
#[derive(
    Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}
pub struct NativeDetails {
    pub instructions: Instructions,
    pub profile_prepared: Observation,
    pub certificate_issued: bool,
    pub first_authenticated_check_in: bool,
    pub channel_ready: bool,
    pub credential_usable: bool,
    pub reauthentication_required: bool,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelOption {
    pub source: ReportSource,
    pub requires_local_administrator: bool,
}
/// Product composition supplies the configured channels and their own protocol facts.
/// The read shares the lifecycle owner's repeatable-read transaction and performs no writes.
pub trait NativeProgress: Send + Sync {
    fn channels(&self) -> Vec<ChannelOption>;
    fn read<'a>(
        &'a self,
        connection: &'a mut sqlx::PgConnection,
        context: &'a Context,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<NativeDetails, Error>> + Send + 'a>,
    >;
}
pub async fn enrollment_status(
    profile: rss_mdm_install_support::StorageProfile,
    database: &crate::Store,
    permission: EnrollmentPermission<'_>,
    id: Uuid,
    native: &dyn NativeProgress,
    credentials: &credentials::Credentials,
) -> Result<Status, Error> {
    permission.check()?;
    let mut tx = database.snapshot(permission.proof().tenant_id()).await?;
    let row = sqlx::query(crate::storage_profile::sql(profile).enrollment_read_enrollment_status_1)
        .bind(permission.proof().tenant_id())
        .bind(id)
        .bind(permission.device())
        .bind(permission.self_service())
        .bind(permission.proof().instance_id())
        .bind(permission.proof().principal_id())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::Forbidden)?;
    let context = context(&row, permission.proof().tenant_id(), id)?;
    let expires_at: i64 = row.try_get("expires_at").map_err(db)?;
    let status = match row.try_get::<String, _>("state").map_err(db)?.as_str() {
        "pending" if expires_at <= context.now => State::Expired,
        "pending" => State::Pending,
        "bound" => State::Bound,
        "cancelled" => State::Cancelled,
        _ => return Err(Error::Corrupt),
    };
    let details = native.read(&mut tx, &context).await?;
    let handoff = match row
        .try_get::<Option<Uuid>, _>("credential_ref")
        .map_err(db)?
    {
        Some(reference) => credentials.available(reference)?,
        None => context.account_driven || context.organization_driven,
    };
    let progress = progress(status, &context, &details, handoff);
    permission.check()?;
    tx.commit().await.map_err(db)?;
    Ok(Status {
        enrollment_id: id,
        status,
        expires_at,
        device_id: context.device.clone(),
        source: context.source,
        instructions: details.instructions,
        progress,
    })
}
fn context(row: &sqlx::postgres::PgRow, tenant: &str, enrollment: Uuid) -> Result<Context, Error> {
    let registration = row
        .try_get::<Option<String>, _>("active_device")
        .map_err(db)?
        .map(|device| {
            let state = match row
                .try_get::<String, _>("registration_state")
                .map_err(db)?
                .as_str()
            {
                "active" => RegistrationState::Active,
                "revoked" => RegistrationState::Revoked,
                _ => return Err(Error::Corrupt),
            };
            Ok(RegistrationContext {
                device,
                state,
                first_authenticated_at: row.try_get("first_authenticated_at").map_err(db)?,
                source_enabled: row.try_get("source_enabled").map_err(db)?,
            })
        })
        .transpose()?;
    let source = match row.try_get::<String, _>("source").map_err(db)?.as_str() {
        "mdm.windows" => ReportSource::MdmWindows,
        "mdm.apple" => ReportSource::MdmApple,
        _ => return Err(Error::Corrupt),
    };
    Ok(Context {
        tenant: tenant.into(),
        device: row.try_get("device").map_err(db)?,
        enrollment,
        source,
        registration,
        now: row.try_get("now").map_err(db)?,
        authorization_version: row.try_get("authorization_version").map_err(db)?,
        account_driven: row.try_get::<String, _>("authority_kind").map_err(db)? == "apple_account",
        organization_driven: matches!(
            row.try_get::<String, _>("authority_kind")
                .map_err(db)?
                .as_str(),
            "apple_ade" | "windows_entra"
        ),
        windows_profile: WindowsProfile::parse(
            row.try_get::<Option<String>, _>("windows_profile")
                .map_err(db)?
                .as_deref(),
        )?,
    })
}
fn progress(state: State, context: &Context, native: &NativeDetails, handoff: bool) -> Progress {
    let diagnostic = diagnostic(state, context, native, handoff);
    Progress {
        profile_prepared: native.profile_prepared,
        certificate_issued: native.certificate_issued,
        first_authenticated_check_in: native.first_authenticated_check_in,
        // reason: native contact proves protocol possession, not an observed system dialog.
        system_confirmation: Observation::Unknown,
        management_ready: diagnostic == Diagnostic::Ready,
        diagnostic,
    }
}
fn diagnostic(
    state: State,
    context: &Context,
    native: &NativeDetails,
    handoff: bool,
) -> Diagnostic {
    match state {
        State::Expired => return Diagnostic::Expired,
        State::Cancelled => return Diagnostic::Cancelled,
        _ => {}
    }
    if let Some(r) = &context.registration {
        match r.state {
            RegistrationState::Revoked => return Diagnostic::Revoked,
            RegistrationState::Active => {}
        }
        if !r.source_enabled {
            return Diagnostic::ChannelUnavailable;
        }
    }
    if matches!(native.instructions, Instructions::Unavailable) {
        return Diagnostic::ChannelUnavailable;
    }
    if native.reauthentication_required || (state == State::Pending && !handoff) {
        return Diagnostic::ReauthenticationRequired;
    }
    if !native.certificate_issued {
        return if native.profile_prepared == Observation::Observed {
            Diagnostic::AwaitingCertificate
        } else {
            Diagnostic::AwaitingSystemConfirmation
        };
    }
    if state == State::Bound && !native.credential_usable {
        return Diagnostic::CredentialUnavailable;
    }
    if !native.first_authenticated_check_in {
        return Diagnostic::AwaitingFirstCheckIn;
    }
    if !native.channel_ready {
        return Diagnostic::AwaitingDeviceToken;
    }
    if state != State::Bound || context.registration.is_none() {
        return Diagnostic::AwaitingFirstCheckIn;
    }
    Diagnostic::Ready
}
/// Records only a real authenticated management exchange under its existing owner transaction.
/// INVARIANT: ENROLLMENT-FIRST-CHECKIN-01 — stale credentials/generations cannot advance progress.
pub async fn record_authenticated_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    principal: &crate::DevicePrincipal,
) -> Result<(), Error> {
    if profile != principal.profile() {
        return Err(crate::Error::Forbidden);
    }

    crate::admission::require_windows_in(profile, c, principal).await?;
    crate::device::store::revalidate_management(profile, c, principal).await?;
    sqlx::query(crate::storage_profile::sql(profile).enrollment_read_record_authenticated_in_1)
        .bind(principal.tenant().to_string())
        .bind(principal.device())
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
