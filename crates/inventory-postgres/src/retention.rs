//! Append-only tenant policy versions share the field-catalog publication lock.
use anyhow::{Result, ensure};
use rss_mdm_inventory::RetentionPolicy;
use rss_request_context::TenantId;
use sqlx::PgConnection;
/// Read an exact immutable policy version without substituting a newer revision.
pub async fn retention_policy_in(
    c: &mut PgConnection,
    tenant: TenantId,
    key: &str,
    revision: u64,
) -> Result<Option<RetentionPolicy>> {
    crate::reader::assert_tenant(c, tenant).await?;
    ensure!(
        revision > 0 && revision <= i64::MAX as u64,
        "invalid retention revision"
    );
    let body:Option<String>=sqlx::query_scalar("SELECT definition::text FROM mdm.retention_policies WHERE tenant_id=$1::uuid AND key=$2 AND revision=$3")
        .bind(tenant.to_string()).bind(key).bind(revision as i64).fetch_optional(c).await?;
    body.map(|v| {
        let policy: RetentionPolicy = serde_json::from_str(&v)?;
        policy.validate()?;
        ensure!(
            policy.key == key && policy.revision == revision,
            "retention identity"
        );
        Ok(policy)
    })
    .transpose()
}
/// Append the next version or confirm an exact replay under the catalog lock.
pub async fn publish_retention_policy_in(
    c: &mut PgConnection,
    tenant: TenantId,
    policy: &RetentionPolicy,
) -> Result<bool> {
    crate::reader::assert_tenant(c, tenant).await?;
    policy.validate()?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2554))")
        .bind(format!("{tenant}:field-catalog"))
        .execute(&mut *c)
        .await?;
    if let Some(old) = retention_policy_in(c, tenant, &policy.key, policy.revision).await? {
        return Ok(old == *policy);
    }
    let latest: Option<i64> = sqlx::query_scalar(
        "SELECT max(revision) FROM mdm.retention_policies WHERE tenant_id=$1::uuid AND key=$2",
    )
    .bind(tenant.to_string())
    .bind(&policy.key)
    .fetch_one(&mut *c)
    .await?;
    if latest.unwrap_or(0) as u64 != policy.revision - 1 {
        return Ok(false);
    }
    sqlx::query("INSERT INTO mdm.retention_policies VALUES($1::uuid,$2,$3,$4::jsonb)")
        .bind(tenant.to_string())
        .bind(&policy.key)
        .bind(policy.revision as i64)
        .bind(serde_json::to_string(policy)?)
        .execute(c)
        .await?;
    Ok(true)
}

/// A resource-wide deletion respects every retained definition's maximum restoration window.
pub async fn minimum_restore_seconds_in(
    c: &mut PgConnection,
    tenant: TenantId,
    field: rss_mdm_inventory::FieldKey,
) -> Result<Option<u32>> {
    crate::reader::assert_tenant(c, tenant).await?;
    let value:Option<i64>=sqlx::query_scalar("SELECT min((p.definition->>'restoreSeconds')::bigint) FROM mdm.field_versions v JOIN mdm.retention_policies p ON p.tenant_id=v.tenant_id AND p.key=v.definition#>>'{timeSeries,retention,key}' AND p.revision=(v.definition#>>'{timeSeries,retention,revision}')::bigint WHERE v.tenant_id=$1::uuid AND v.field=$2 AND v.definition IS NOT NULL")
        .bind(tenant.to_string()).bind(field.as_str()).fetch_one(c).await?;
    value
        .map(|v| u32::try_from(v).map_err(Into::into))
        .transpose()
}
