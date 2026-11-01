//! Published Scope facts read on the caller's connection; no pool or transaction is created.
use crate::sources::ScopeInput;
use rss_mdm_inventory::Channel;
use rss_mdm_inventory_service::objects::DeviceObject;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
/// One bounded frozen source fact; channel qualification is owned by Scope.
pub struct SourceRow {
    pub source: usize,
    pub unknown: bool,
    pub input: DeviceObject,
}
fn invariant() -> sqlx::Error {
    sqlx::Error::Protocol("Scope result invariant".into())
}
pub async fn resolution_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<Option<(Uuid, i64, ScopeInput, bool)>, sqlx::Error> {
    let status = rss_mdm_scope_postgres::admission_on(profile, c, tenant, scope).await?;
    Ok(published_on(profile, c, tenant, scope)
        .await?
        .map(|(run, revision, frozen)| (run, revision, frozen, status["state"] == "fresh")))
}

/// Current publication interpreted in the caller's read snapshot, without business locks.
pub async fn read_resolution_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<Option<(Uuid, i64, ScopeInput, bool)>, sqlx::Error> {
    let status = rss_mdm_scope_postgres::state_on(profile, c, tenant, scope).await?;
    Ok(published_on(profile, c, tenant, scope)
        .await?
        .map(|(run, revision, frozen)| (run, revision, frozen, status["state"] == "fresh")))
}

/// Published head and its immutable input; safe inside a read-only page snapshot.
/// Current execution admission remains the responsibility of the protected owner admission.
pub async fn published_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<Option<(Uuid, i64, ScopeInput)>, sqlx::Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).results_published_on_1)
        .bind(tenant.to_string())
        .bind(scope)
        .fetch_optional(c)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let frozen = serde_json::from_value(row.try_get("input")?).map_err(|_| invariant())?;
    Ok(Some((
        row.try_get("resolution")?,
        row.try_get("resolution_revision")?,
        frozen,
    )))
}

pub async fn source_rows_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    channel: Channel,
    device: &str,
) -> Result<Vec<SourceRow>, sqlx::Error> {
    let rows = sqlx::query(crate::storage_profile::sql(profile).results_source_rows_on_1)
        .bind(tenant.to_string())
        .bind(run)
        .bind(device)
        .bind(channel.as_str())
        .fetch_all(c)
        .await?;
    if rows.len() > 16000 {
        return Err(invariant());
    }
    rows.into_iter()
        .map(|r| {
            Ok(SourceRow {
                source: r.try_get::<i32, _>("source")? as usize,
                unknown: r.try_get("unknown")?,
                input: serde_json::from_value(r.try_get("input")?).map_err(|_| invariant())?,
            })
        })
        .collect()
}

pub async fn historical_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    run: Uuid,
) -> Result<ScopeInput, sqlx::Error> {
    let input: serde_json::Value =
        sqlx::query_scalar(crate::storage_profile::sql(profile).results_historical_on_1)
            .bind(tenant.to_string())
            .bind(scope)
            .bind(run)
            .fetch_optional(c)
            .await?
            .ok_or(sqlx::Error::RowNotFound)?;
    serde_json::from_value(input).map_err(|_| invariant())
}

/// A bounded page of devices represented by frozen Scope sources; Execution selects eligibility.
pub async fn source_devices_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    sources: &[i32],
    channel: Channel,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<String>, sqlx::Error> {
    if !(1..=1001).contains(&limit) || sources.len() > 1000 {
        return Err(invariant());
    }
    sqlx::query_scalar(crate::storage_profile::sql(profile).results_source_devices_on_1)
        .bind(tenant.to_string())
        .bind(run)
        .bind(sources)
        .bind(channel.as_str())
        .bind(after)
        .bind(limit as i64)
        .fetch_all(c)
        .await
}
/// Read frozen object facts without interpreting registration or channel authority.
pub async fn source_objects_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    sources: &[i32],
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<rss_mdm_scope_postgres::SourceMember>, sqlx::Error> {
    if !(1..=1001).contains(&limit) || sources.len() > 1000 {
        return Err(invariant());
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).results_source_objects_on_1)
        .bind(tenant.to_string())
        .bind(run)
        .bind(sources)
        .bind(after)
        .bind(limit as i64)
        .fetch_all(c)
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok(rss_mdm_scope_postgres::SourceMember {
                object: r.try_get("object_key")?,
                unknown: r.try_get("unknown")?,
                input: r.try_get("input")?,
            })
        })
        .collect()
}

/// Tenant-bound published heads for one-statement composition with caller-owned facts.
/// Parameters: $1 tenant, $2 scope; no channel or execution judgment is embedded here.

/// Frozen source facts for bounded caller-owned object qualification and pagination.
/// Parameters: $1 tenant, $2 run, $3 source indexes. The caller supplies its page bound.
pub const SOURCE_MEMBER_FACTS_SQL: &str = "SELECT tenant_id,input,unknown FROM mdm_scope.scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND source=ANY($3)";
