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

pub(super) async fn read(
    app: &Context,
    p: &DevicePrincipal,
    binding: Option<Uuid>,
) -> Result<Status, Error> {
    let rt = app.runtime()?;
    if p.tenant() != app.tenant {
        return Err(Error::Unauthorized);
    }
    let tenant = p.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let user_id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND binding=$2 AND kind='user'")
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
    store::fence(&mut tx, &tenant).await?;
    let object = rss_mdm_device_service::planning::PlanningObjects::paired_in(
        &mut tx,
        p.tenant(),
        p.device(),
    )
    .await
    .map_err(db)?;
    if !object
        .members
        .iter()
        .any(|m| m.registration_id == p.registration() && m.generation == p.generation())
    {
        return Err(Error::Unauthorized);
    }
    let member = object
        .members
        .iter()
        .find(|m| m.channel == rss_mdm_inventory::Channel::Mdm)
        .ok_or(Error::Unauthorized)?;
    store::current_object(app, &mut tx, &object, member.registration_id).await?;
    if user.as_ref().is_some_and(|u| u.object != object) {
        return Err(Error::Unauthorized);
    }
    let now = store::now(&mut tx).await?;
    let application_observed =
        deployment::application(&mut tx, rt, p.tenant(), member.registration_id, now).await?;
    let login = deployment::configuration_for_object(&mut tx, app.tenant, &object).await?;
    let profile_observed = deployment::profile(
        &mut tx,
        app,
        member.registration_id,
        member.generation,
        &login,
    )
    .await?;
    let device_id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND registration=$2 AND kind='device'")
        .bind(&tenant).bind(member.registration_id).fetch_optional(&mut *tx).await.map_err(db)?;
    let device = match device_id {
        Some(id) => Some(store::source(&mut tx, &tenant, id).await?),
        None => None,
    };
    let device_registered = device.as_ref().is_some_and(|s| {
        !s.revoked
            && s.object == object
            && s.login_configuration == login
            && rt.fingerprint().is_ok_and(|f| s.configuration == f)
    });
    let user_registered = match &user {
        Some(u) => {
            identity_current && admitted(store::current_user(app, &mut tx, u.id, false).await)?
        }
        None => false,
    };
    let login_ready = if user_registered && application_observed && profile_observed {
        admitted(
            store::current_user(app, &mut tx, user_id.ok_or(Error::Unauthorized)?, true).await,
        )?
    } else {
        false
    };
    let password_exchange = if let Some(user) = &user {
        use rss_mdm_agent_wire::platform_sso::{
            PasswordExchangeState as State, PasswordExchangeStatus,
        };
        let last: Option<(Uuid, String, i64)> = sqlx::query_as("SELECT id,state,expires_at FROM mdm_apple.psso_password_attempts WHERE tenant_id=$1::uuid AND source=$2 AND version=$3 ORDER BY expires_at DESC,id DESC LIMIT 1")
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
                    _ => return Err(Error::Unavailable(crate::Failure::Database)),
                },
            })
        })
        .transpose()?
    } else {
        None
    };
    let public = |s: store::Source| SourceStatus {
        id: s.id,
        version: s.version,
        revoked: s.revoked,
        signing_key: s.signing,
        encryption_key: s.encryption,
    };
    Ok(Status {
        password_exchange,
        application_observed,
        profile_observed,
        device_registered,
        user_registered,
        login_ready,
        device_source: device.map(public),
        user_source: user.map(public),
        registration_trust: RegistrationTrust::MdmBootstrapPop,
        hardware_attested: false,
    })
}
