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
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Vec<SourceRow>, sqlx::Error> {
    let rows = sqlx::query(crate::storage_profile::sql(profile).results_source_rows_on_1)
        .bind(tenant.to_string())
        .bind(run)
        .bind(device.into_uuid())
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
#[allow(
    clippy::too_many_arguments,
    reason = "source projection retains explicit product, scope, publication and result coordinates"
)]
pub async fn source_devices_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    sources: &[i32],
    channel: Channel,
    after: Option<&rss_mdm_agent_wire::DeviceId>,
    limit: usize,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    if !(1..=1001).contains(&limit) || sources.len() > 1000 {
        return Err(invariant());
    }
    sqlx::query_scalar::<_, Uuid>(crate::storage_profile::sql(profile).results_source_devices_on_1)
        .bind(tenant.to_string())
        .bind(run)
        .bind(sources)
        .bind(channel.as_str())
        .bind(after.map(|id| id.into_uuid()))
        .bind(limit as i64)
        .fetch_all(c)
        .await?
        .into_iter()
        .map(|id| rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|_| invariant()))
        .collect()
}
/// Read frozen object facts without interpreting registration or channel authority.
pub async fn source_objects_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    sources: &[i32],
    after: Option<rss_mdm_agent_wire::ObjectRef>,
    limit: usize,
) -> Result<Vec<rss_mdm_scope_postgres::SourceMember>, sqlx::Error> {
    if !(1..=1001).contains(&limit) || sources.len() > 1000 {
        return Err(invariant());
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).results_source_objects_on_1)
        .bind(tenant.to_string())
        .bind(run)
        .bind(sources)
        .bind(after.map(|o| o.kind()))
        .bind(after.map(|o| o.uuid()))
        .bind(limit as i64)
        .fetch_all(c)
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok(rss_mdm_scope_postgres::SourceMember {
                object: rss_mdm_agent_wire::ObjectRef::from_parts(
                    r.try_get("object_kind")?,
                    r.try_get("object_id")?,
                )
                .map_err(|_| invariant())?,
                unknown: r.try_get("unknown")?,
                input: r.try_get("input")?,
            })
        })
        .collect()
}
