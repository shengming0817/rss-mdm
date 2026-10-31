//! Apple admission preserves control-plane constraints while deferring endpoint OS evidence.
use crate::{Error, database::db};
pub async fn eligible_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    registration: uuid::Uuid,
    generation: i64,
    template: &rss_mdm_resource::NativeCollectionDefinition,
) -> Result<bool, Error> {
    let purpose:Option<String>=sqlx::query_scalar("SELECT purpose FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND state='active'")
        .bind(tenant.to_string()).bind(registration).bind(generation).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(purpose) = purpose else {
        return Ok(false);
    };
    let rights:Option<i32>=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'")
        .bind(tenant.to_string()).bind(registration).fetch_optional(&mut *c).await.map_err(db)?;
    let required = template
        .spec()
        .adapter
        .apple_rights()
        .ok_or(Error::Unsupported)?
        | 1040;
    if rights.is_none_or(|rights| rights & required != required) {
        return Ok(false);
    }
    let user = match &template.spec().scope {
        rss_mdm_resource::TemplateScope::Device => "",
        rss_mdm_resource::TemplateScope::User { identity } => identity,
        _ => return Ok(false),
    };
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND state='active')")
        .bind(tenant.to_string()).bind(registration).bind(generation).bind(user).fetch_one(c).await.map_err(db)?;
    if !active {
        return Ok(false);
    }
    let mut requirements = template.spec().applicability.clone();
    requirements.minimum_os_version = None;
    Ok(requirements.allows(
        &Default::default(),
        &purpose,
        &[template.spec().adapter.capability().into()].into(),
    ))
}
