//! Manual storage borrows the host transaction, including its replay receipt and audit.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{FieldKey, SourceFact};
use rss_request_context::TenantId;
use sqlx::Row;
/// Versioned manual value or tombstone. Revisions survive deletion.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Assignment {
    /// Stable device identity.
    pub device: String,
    /// Manual dictionary key.
    pub field: FieldKey,
    /// CAS revision.
    pub revision: i64,
    /// Current value, provenance and retained last-known value.
    pub fact: SourceFact,
}
/// Read only the caller's bounded authorized device set.
pub async fn manual_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    devices: &[String],
) -> Result<Vec<Assignment>> {
    ensure!(devices.len() <= 10_000, "asset device budget exceeded");
    crate::reader::assert_tenant(c, tenant).await?;
    let rows=sqlx::query("SELECT device,field,revision,fact::text FROM mdm.manual_assignments WHERE tenant_id=$1::uuid AND device=ANY($2) ORDER BY device,field").bind(tenant.to_string()).bind(devices).fetch_all(c).await?;
    rows.into_iter()
        .map(|r| {
            Ok(Assignment {
                device: r.try_get("device")?,
                field: FieldKey::parse(r.try_get::<&str, _>("field")?)?,
                revision: r.try_get("revision")?,
                fact: serde_json::from_str(r.try_get::<&str, _>("fact")?)?,
            })
        })
        .collect()
}
/// Compare and set one Manual record. Returns None on revision conflict, never commits.
/// The host must authorize the device, serialize creation, and atomically save receipt and audit.
pub async fn assign_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    device: &str,
    field: FieldKey,
    expected: i64,
    fact: &SourceFact,
) -> Result<Option<i64>> {
    ensure!(
        field.definition().manual && (0..i64::MAX).contains(&expected),
        "invalid manual assignment"
    );
    rss_mdm_inventory::resolve(field, vec![fact.clone()])?;
    crate::reader::assert_tenant(c, tenant).await?;
    let document = serde_json::to_string(fact)?;
    let revision=sqlx::query_scalar("INSERT INTO mdm.manual_assignments(tenant_id,device,field,revision,fact) SELECT $1::uuid,$2,$3,1,$5::jsonb WHERE $4=0 ON CONFLICT(tenant_id,device,field) DO NOTHING RETURNING revision")
        .bind(tenant.to_string()).bind(device).bind(field.as_str()).bind(expected).bind(&document).fetch_optional(&mut *c).await?;
    if revision.is_some() {
        return Ok(revision);
    }
    Ok(sqlx::query_scalar("UPDATE mdm.manual_assignments SET revision=revision+1,fact=$5::jsonb WHERE tenant_id=$1::uuid AND device=$2 AND field=$3 AND revision=$4 RETURNING revision")
        .bind(tenant.to_string()).bind(device).bind(field.as_str()).bind(expected).bind(document).fetch_optional(c).await?)
}
