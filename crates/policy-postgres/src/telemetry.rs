//! Exact Policy publications consumed by the telemetry application.
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;
/// Read and hold the current enabled publication through the caller's transaction.
pub async fn current_on(
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    version: Uuid,
) -> Result<Option<(rss_mdm_policy::Definition, Value)>, sqlx::Error> {
    sqlx::query("SELECT mdm_policy.lock_policy($1)")
        .bind(policy)
        .execute(&mut *c)
        .await?;
    let row:Option<(Value,Value)>=sqlx::query_as("SELECT p.definition,v.frozen FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.id=$2 AND p.current_version=$3 AND p.state='enabled' AND v.action_kind='telemetry_profile'").bind(tenant.to_string()).bind(policy).bind(version).fetch_optional(c).await?;
    row.map(|(definition, frozen)| {
        Ok((
            serde_json::from_value(definition)
                .map_err(|_| sqlx::Error::Protocol("invalid Policy definition".into()))?,
            frozen,
        ))
    })
    .transpose()
}
/// Interpret an already issued version independently of the current Policy head.
pub async fn historical_on(
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    version: Uuid,
) -> Result<Option<Value>, sqlx::Error> {
    sqlx::query_scalar("SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND policy=$2 AND id=$3 AND action_kind='telemetry_profile'").bind(tenant.to_string()).bind(policy).bind(version).fetch_optional(c).await
}
/// Bounded current candidates; the caller performs device-specific admission.
pub async fn candidates_on(
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<Vec<(Uuid, Uuid, Value)>, sqlx::Error> {
    sqlx::query_as("SELECT p.id,p.current_version,p.definition FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND v.action_kind='telemetry_profile' ORDER BY p.id LIMIT 257").bind(tenant.to_string()).fetch_all(c).await
}
/// Fence delivery to the exact current publication without changing historical receipt validity.
pub async fn is_current_on(
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    version: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query("SELECT mdm_policy.lock_policy($1)")
        .bind(policy)
        .execute(&mut *c)
        .await?;
    Ok(sqlx::query_scalar::<_,bool>("SELECT true FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2 AND current_version=$3 AND state='enabled'").bind(tenant.to_string()).bind(policy).bind(version).fetch_optional(c).await?==Some(true))
}
