//! Reuse native application facts and profile verification; acknowledgements are not readiness.
use super::*;
use crate::database::db;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;

pub(crate) async fn application(
    c: &mut PgConnection,
    rt: &Runtime,
    tenant: TenantId,
    registration: Uuid,
    now: i64,
) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)=$4 AND mdm_apple.application_valid_until($1,$2,$3) IS NOT NULL")
        .bind(registration)
        .bind(
            serde_json::to_value(rt.qualification_configuration()?)
                .map_err(|_| Error::Malformed)?,
        )
        .bind(now)
        .bind(tenant.to_string())
        .fetch_one(c)
        .await
        .map_err(db)
}

pub(super) async fn profile(
    c: &mut PgConnection,
    app: &Context,
    registration: Uuid,
    generation: i64,
) -> Result<bool, Error> {
    let expected = app.runtime()?.profile()?;
    let tenant = app.tenant.to_string();
    let operations:Vec<Uuid>=sqlx::query_scalar("SELECT operation FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key='' AND identifier=$4 AND profile=$5 AND present AND retired_at IS NULL AND observed_at IS NOT NULL LIMIT 2")
        .bind(&tenant).bind(registration).bind(generation).bind(expected.identifier).bind(expected.uuid).fetch_all(&mut *c).await.map_err(db)?;
    if operations.len() != 1 {
        return Ok(false);
    }
    Ok(matches!(
        crate::profiles::assessment(c, &tenant, operations[0]).await?,
        rss_mdm_apple_mdm::native::profiles::Verification::Matched
    ))
}
pub(super) async fn ready(
    app: &Context,
    c: &mut PgConnection,
    object: &rss_mdm_inventory_service::objects::DeviceObject,
    now: i64,
) -> Result<(), Error> {
    let member = object
        .members
        .iter()
        .find(|m| m.channel == rss_mdm_inventory::Channel::Mdm)
        .ok_or(Error::Unauthorized)?;
    if !application(c, app.runtime()?, app.tenant, member.registration_id, now).await?
        || !profile(c, app, member.registration_id, member.generation).await?
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// Called by the existing profile dispatcher, before a native mutation is emitted.
pub(crate) async fn admit_profile(
    c: &mut PgConnection,
    apple: &crate::Apple,
    p: &rss_mdm_registration_service::DevicePrincipal,
    profile: &rss_mdm_apple_mdm::native::profiles::ProfileInput,
    now: i64,
) -> Result<bool, Error> {
    // PlatformSSO is an Apple capability shared by independent providers.
    let relevant = profile.identifier.starts_with("rss.platform-sso.")
        || apple.platform_sso.as_deref().is_some_and(|rt| {
            profile.payloads.iter().any(|p| {
                p.schema == "mdm/profiles/com.apple.extensiblesso.yaml"
                    && p.fields.to_plist().is_ok_and(|f| {
                        f.get("TeamIdentifier").and_then(plist::Value::as_string)
                            == Some(rt.configuration.team_id.as_str())
                            && f.get("ExtensionIdentifier")
                                .and_then(plist::Value::as_string)
                                == Some(rt.configuration.extension_id.as_str())
                    })
            })
        });
    if !relevant {
        return Ok(true);
    }
    let rt = apple.platform_sso.as_deref().ok_or(Error::Unsupported)?;
    if serde_json::to_value(profile).map_err(|_| Error::Malformed)?
        != serde_json::to_value(rt.profile()?).map_err(|_| Error::Malformed)?
    {
        return Err(Error::Conflict);
    }
    application(c, rt, p.tenant(), p.registration(), now).await
}
