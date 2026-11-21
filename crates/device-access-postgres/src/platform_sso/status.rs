//! Diagnostic snapshots never serve as an admission credential.
use super::*;
use crate::database::db;
use rss_mdm_agent_wire::platform_sso::{RegistrationTrust, SourceStatus, Status};
use rss_mdm_registration_service::DevicePrincipal;
use uuid::Uuid;

fn admitted<T>(result: Result<T, Error>) -> Result<bool, Error> {
    match result {
        Ok(_) => Ok(true),
        Err(Error::Unauthorized | Error::Forbidden | Error::Conflict | Error::NotFound) => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

use rss_mdm_agent_wire::{
    DeviceId,
    platform_sso::{PasswordExchangeState, PasswordExchangeStatus},
};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_registration_service::device::endpoints::DaRegistration;
use rss_transactional_messaging::fence::ExecutionBinding;
use sqlx::PgConnection;

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    Unobserved,
    Untrusted,
    Conflict,
    Expired,
    Revoked,
    Trusted,
}
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Unobserved,
    Historical,
    Revoked,
    Current,
}
#[derive(Clone, Copy, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Unknown,
    Incomplete,
    Recovering,
    Ready,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    authority: Uuid,
    key_fingerprint: String,
    sequence: i64,
    policy: Uuid,
    policy_version: Uuid,
    issued_at: i64,
    expires_at: i64,
    application_id: String,
    application_version: String,
    profile_identifier: String,
    profile_uuid: Uuid,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagementStatus {
    installation: Uuid,
    device: DeviceId,
    binding: Option<Uuid>,
    binding_generation: Option<i64>,
    deployment: DeploymentState,
    evidence: Vec<Evidence>,
    device_registration: RegistrationState,
    user_registration: RegistrationState,
    login: Readiness,
    password_exchange: Option<PasswordExchangeState>,
}
struct Facts {
    deployment: DeploymentState,
    evidence: Vec<Evidence>,
    device: Option<store::Source>,
    user: Option<store::Source>,
    device_registered: bool,
    user_registered: bool,
    login_ready: bool,
    password_exchange: Option<PasswordExchangeStatus>,
}
enum Target<'a> {
    Device(&'a DevicePrincipal),
    Management(DeviceId),
}
async fn deployment_state(
    execution: ExecutionBinding,
    app: &Context,
    c: &mut PgConnection,
    object: &DaRegistration,
    now: i64,
    configured: bool,
) -> Result<(DeploymentState, Vec<Evidence>), Error> {
    let rt = app.runtime()?;
    let values = match rt
        .evidence
        .configurations_on(c, execution.tenant(), app.installation, object)
        .await
    {
        Ok(values) => values,
        Err(Error::Malformed | Error::Forbidden | Error::Unauthorized) => {
            return Ok((DeploymentState::Untrusted, vec![]));
        }
        Err(e) => return Err(e),
    };
    let fingerprints = rt.evidence.fingerprints();
    let mut evidence = vec![];
    let mut revoked = false;
    let mut expired = false;
    for v in values {
        let rss_mdm_device_access::deployment::Deployment::Macos {
            application_id,
            application_version,
            profile_identifier,
            profile_uuid,
            ..
        } = v.deployment
        else {
            continue;
        };
        revoked |= v.revoked;
        expired |= v.expires_at <= now;
        evidence.push(Evidence {
            authority: v.authority,
            key_fingerprint: fingerprints
                .get(&v.authority)
                .ok_or(Error::Corrupt)?
                .clone(),
            sequence: v.sequence,
            policy: v.policy,
            policy_version: v.policy_version,
            issued_at: v.issued_at,
            expires_at: v.expires_at,
            application_id,
            application_version,
            profile_identifier,
            profile_uuid,
        });
    }
    let state = if evidence.is_empty() {
        DeploymentState::Unobserved
    } else if revoked {
        DeploymentState::Revoked
    } else if expired {
        DeploymentState::Expired
    } else if !configured {
        DeploymentState::Untrusted
    } else {
        match deployment::ready(execution, app, c, object, now).await {
            Ok(()) => DeploymentState::Trusted,
            Err(Error::Conflict) => DeploymentState::Conflict,
            Err(Error::Unauthorized | Error::Forbidden | Error::Malformed | Error::NotFound) => {
                DeploymentState::Untrusted
            }
            Err(e) => return Err(e),
        }
    };
    Ok((state, evidence))
}
async fn facts(
    execution: ExecutionBinding,
    app: &Context,
    mut tx: &mut PgConnection,
    target: Target<'_>,
    binding: Option<Uuid>,
) -> Result<Facts, Error> {
    let rt = app.runtime()?;
    let tenant = execution.tenant().to_string();
    let user_id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM rss_da.psso_sources WHERE tenant_id=$1::uuid AND binding=$2 AND kind='user'")
        .bind(&tenant).bind(binding).fetch_optional(&mut *tx).await.map_err(db)?;
    let user = match user_id {
        Some(id) => Some(store::read(&mut tx, &tenant, id).await?),
        None => None,
    };
    // Identity guard precedes the device watermark, even for diagnostic reads.
    let identity_current = match &user {
        Some(s) => admitted(service::admit(app, &mut tx, s).await)?,
        None => false,
    };
    let object = DaRegistration {
        device: match target {
            Target::Device(p) => *crate::delivery::resolve_on(&mut tx, p).await?.device(),
            Target::Management(device) => device,
        },
    };
    if user.as_ref().is_some_and(|u| u.object != object) {
        return Err(Error::Unauthorized);
    }
    store::current_object(execution, &mut tx, &object).await?;
    if let Some(previous) = &user {
        let current = store::read(&mut tx, &tenant, previous.id).await?;
        if current.version != previous.version || current.revoked != previous.revoked {
            return Err(Error::ReadConflict);
        }
    }
    let now = store::now(&mut tx).await?;
    let login =
        match deployment::configuration_for_object(&mut tx, execution.tenant(), &object).await {
            Ok(login) => Some(login),
            Err(Error::NotFound | Error::Conflict) => None,
            Err(e) => return Err(e),
        };
    let (deployment, evidence) =
        deployment_state(execution, app, &mut tx, &object, now, login.is_some()).await?;
    let qualified = deployment == DeploymentState::Trusted;

    let device_id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM rss_da.psso_sources WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND kind = 'device'")
        .bind(&tenant).bind(object.device.into_uuid()).fetch_optional(&mut *tx).await.map_err(db)?;
    let device = match device_id {
        Some(id) => Some(store::source(&mut tx, &tenant, id).await?),
        None => None,
    };
    let device_registered = device.as_ref().is_some_and(|s| {
        !s.revoked
            && s.object == object
            && Some(&s.login_configuration) == login.as_ref()
            && rt.fingerprint().is_ok_and(|f| s.configuration == f)
    });
    let user_registered = match &user {
        Some(u) => {
            identity_current
                && admitted(store::current_user(execution, app, &mut tx, u.id, false).await)?
        }
        None => false,
    };
    let login_ready = if user_registered && qualified {
        admitted(
            store::current_user(
                execution,
                app,
                &mut tx,
                user_id.ok_or(Error::Unauthorized)?,
                true,
            )
            .await,
        )?
    } else {
        false
    };
    let password_exchange = if let Some(user) = &user {
        use rss_mdm_agent_wire::platform_sso::{
            PasswordExchangeState as State, PasswordExchangeStatus,
        };
        let last: Option<(Uuid, String, i64)> = sqlx::query_as("SELECT id,state,expires_at FROM rss_da.psso_password_attempts WHERE tenant_id=$1::uuid AND source=$2 AND version=$3 ORDER BY expires_at DESC,id DESC LIMIT 1")
            .bind(&tenant).bind(user.id).bind(user.version).fetch_optional(&mut *tx).await.map_err(db)?;
        last.map(|(attempt_id, state, expires)| {
            Ok::<_, Error>(PasswordExchangeStatus {
                attempt_id,
                state: match state.as_str() {
                    "verifying" if expires <= now => State::Unknown,
                    "verifying" => State::Verifying,
                    "succeeded" => State::Succeeded,
                    "rejected" => State::Rejected,
                    "unavailable" => State::Unavailable,
                    _ => return Err(Error::Storage),
                },
            })
        })
        .transpose()?
    } else {
        None
    };

    Ok(Facts {
        deployment,
        evidence,
        device,
        user,
        device_registered,
        user_registered,
        login_ready,
        password_exchange,
    })
}
fn coordinate(s: store::Source) -> SourceStatus {
    SourceStatus {
        id: s.id,
        version: s.version,
        revoked: s.revoked,
        signing_key: s.signing,
        encryption_key: s.encryption,
    }
}
pub async fn read(
    execution: ExecutionBinding,
    app: &Context,
    p: &DevicePrincipal,
    binding: Option<Uuid>,
) -> Result<Status, Error> {
    if execution != p.binding() {
        return Err(Error::Unauthorized);
    }
    let mut tx = app.access.begin(&p.tenant().to_string()).await?;
    let f = facts(execution, app, &mut tx, Target::Device(p), binding).await?;
    let trusted = f.deployment == DeploymentState::Trusted;
    Ok(Status {
        password_exchange: f.password_exchange,
        application_observed: trusted,
        profile_observed: trusted,
        device_registered: f.device_registered,
        user_registered: f.user_registered,
        login_ready: f.login_ready,
        device_source: f.device.map(coordinate),
        user_source: f.user.map(coordinate),
        registration_trust: if p.kind()
            == rss_mdm_registration_service::device::RegistrationKind::DaDevice
        {
            RegistrationTrust::DaDevicePop
        } else {
            RegistrationTrust::MdmBootstrapPop
        },
        hardware_attested: false,
    })
}
fn registration(source: Option<&store::Source>, current: bool) -> RegistrationState {
    match source {
        None => RegistrationState::Unobserved,
        Some(s) if s.revoked => RegistrationState::Revoked,
        Some(_) if current => RegistrationState::Current,
        Some(_) => RegistrationState::Historical,
    }
}
impl crate::Service {
    pub async fn platform_status(
        &self,
        app: &Context,
        actor: &AuthorizedPrincipal,
        device: DeviceId,
        binding: Option<Uuid>,
    ) -> Result<ManagementStatus, Error> {
        self.read_with_session(actor, (app, actor, device, binding), |ctx, c| {
            Box::pin(async move {
                let (app, p, device, binding) = *ctx;
                crate::device_access::service::authorize(c, p, &device, Permission::OperationRead)
                    .await?;
                let generation = if let Some(id) = binding {
                    crate::device_access::service::authorize(
                        c,
                        p,
                        &device,
                        Permission::AccountWrite,
                    )
                    .await?;
                    let b = crate::device_access::storage::get_in(
                        c,
                        Uuid::parse_str(p.tenant_id()).map_err(|_| Error::Malformed)?,
                        id,
                    )
                    .await?;
                    if b.device != device {
                        return Err(Error::NotFound);
                    }
                    Some(b.generation)
                } else {
                    None
                };
                if app.platform_sso.is_none() {
                    store::current_object(p.binding(), c, &DaRegistration { device }).await?;
                    return Ok(ManagementStatus {
                        installation: app.installation,
                        device,
                        binding,
                        binding_generation: generation,
                        deployment: DeploymentState::Unobserved,
                        evidence: vec![],
                        device_registration: RegistrationState::Unobserved,
                        user_registration: RegistrationState::Unobserved,
                        login: Readiness::Unknown,
                        password_exchange: None,
                    });
                }
                let f = facts(p.binding(), app, c, Target::Management(device), binding).await?;
                let user_registration = registration(
                    f.user.as_ref(),
                    f.user_registered
                        && f.user
                            .as_ref()
                            .is_some_and(|u| Some(u.binding_generation) == generation),
                );
                let device_registration = registration(f.device.as_ref(), f.device_registered);
                let exchange = f
                    .password_exchange
                    .filter(|_| {
                        user_registration == RegistrationState::Current
                            && device_registration == RegistrationState::Current
                            && f.deployment == DeploymentState::Trusted
                    })
                    .map(|s| s.state);
                let login = if f.login_ready && user_registration == RegistrationState::Current {
                    Readiness::Ready
                } else if matches!(
                    exchange,
                    Some(
                        PasswordExchangeState::Verifying
                            | PasswordExchangeState::Unavailable
                            | PasswordExchangeState::Unknown
                    )
                ) {
                    Readiness::Recovering
                } else if f.deployment == DeploymentState::Unobserved
                    && f.device.is_none()
                    && f.user.is_none()
                {
                    Readiness::Unknown
                } else {
                    Readiness::Incomplete
                };
                Ok(ManagementStatus {
                    installation: app.installation,
                    device,
                    binding,
                    binding_generation: generation,
                    deployment: f.deployment,
                    evidence: f.evidence,
                    device_registration,
                    user_registration,
                    login,
                    password_exchange: exchange,
                })
            })
        })
        .await
    }
}
