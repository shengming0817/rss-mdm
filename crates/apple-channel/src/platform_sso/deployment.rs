//! Reuse native application facts and profile verification; acknowledgements are not readiness.
use super::*;
use crate::database::db;
use rss_mdm_inventory::{CollectionScope, FieldKey, ReportSource, Scalar, State};
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
    let source = ReportSource::MdmApple;
    let Some(epoch) = rss_mdm_registration_service::device::store::report_epoch_in(
        c,
        &tenant.to_string(),
        registration,
        source,
    )
    .await?
    else {
        return Ok(false);
    };
    let rows = rss_mdm_inventory_postgres::field_in(
        c,
        tenant,
        registration,
        source,
        epoch,
        FieldKey::parse("device.software.apple.installed_applications")
            .map_err(|_| Error::Malformed)?,
    )
    .await
    .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let mut observed = false;
    for row in rows {
        if row.fact.evidence.scope != CollectionScope::Device {
            continue;
        }
        if row.fact.evidence.received_at > now || row.fact.evidence.received_at < now - 86400 {
            return Ok(false);
        }
        let State::Known(Scalar::Array(items)) = row.fact.state else {
            return Ok(false);
        };
        let matches = items
            .iter()
            .filter_map(|i| match i {
                Scalar::Object(v) => Some(v),
                _ => None,
            })
            .filter(|v| {
                v.get("id") == Some(&Scalar::String(rt.configuration.application_id.clone()))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1
            || matches[0].get("version")
                != Some(&Scalar::String(
                    rt.configuration.application_version.clone(),
                ))
            || matches[0].get("installing") == Some(&Scalar::Boolean(true))
        {
            return Ok(false);
        }
        observed = true;
    }
    Ok(observed)
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
        crate::profiles::assessment(c, &app.protection, &tenant, operations[0]).await?,
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
    let relevant = profile.payloads.iter().any(|p| {
        p.schema == "mdm/profiles/com.apple.extensiblesso.yaml"
            && p.fields
                .to_plist()
                .is_ok_and(|f| f.contains_key("PlatformSSO"))
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
