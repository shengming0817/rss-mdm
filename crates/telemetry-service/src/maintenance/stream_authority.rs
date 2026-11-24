//! One immutable publication per committed transaction. Device intake and catalog
//! writers share the fences held through verification, intent admission or dispatch.
use super::{Error, Request, Service, StreamTarget};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::collections::BTreeSet;
use uuid::Uuid;

type Cursor = (Uuid, Uuid);

pub(super) async fn lock(
    c: &mut PgConnection,
    tenant: TenantId,
    input: &Request,
) -> Result<(), Error> {
    rss_mdm_registration_service::device::store::lock_channel(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &tenant.to_string(),
        &input.device,
        rss_mdm_inventory::Channel::Agent,
    )
    .await
    .map_err(|_| Error::Storage)?;
    rss_mdm_inventory_postgres::lock_catalog_read_in(c, tenant)
        .await
        .map_err(|_| Error::Storage)
}

/// A true return proves the current tail was exhausted under the caller's locks.
/// Each false return must be committed before attempting another publication.
pub(super) async fn advance(
    service: &Service,
    c: &mut PgConnection,
    tenant: TenantId,
    input: &Request,
    target: &StreamTarget,
    binding: &[u8],
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2 AND expires_at<=clock_timestamp()")
        .bind(tenant.to_string()).bind(input.id).execute(&mut *c).await?;
    let revision = rss_mdm_inventory_postgres::catalog_revision_in(c, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let limit = i64::from(service.maintenance_policy.authorization_bytes.get());
    let row = sqlx::query("SELECT policy,version,found, catalog_revision=$3 AND byte_limit=$4 AND expires_at>clock_timestamp() AS valid
       FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(tenant.to_string()).bind(input.id).bind(revision).bind(limit).fetch_optional(&mut *c).await?;
    let mut cursor = None;
    let mut found = false;
    if let Some(row) = &row
        && row.try_get::<bool, _>("valid")?
    {
        cursor = row
            .try_get::<Option<Uuid>, _>("policy")?
            .zip(row.try_get::<Option<Uuid>, _>("version")?);
        found = row.try_get("found")?;
    }
    let query = if let Some((policy, version)) = cursor {
        sqlx::query_as::<_,Cursor>("SELECT policy,policy_version FROM mdm_telemetry.batches
            WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND epoch=$4 AND (policy,policy_version)>($5,$6)
            ORDER BY policy,policy_version LIMIT 1")
            .bind(tenant.to_string()).bind(input.device.into_uuid()).bind(target.source.as_str()).bind(target.epoch).bind(policy).bind(version)
    } else {
        sqlx::query_as::<_,Cursor>("SELECT policy,policy_version FROM mdm_telemetry.batches
            WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND epoch=$4 ORDER BY policy,policy_version LIMIT 1")
            .bind(tenant.to_string()).bind(input.device.into_uuid()).bind(target.source.as_str()).bind(target.epoch)
    };
    let Some((policy, version)) = query.fetch_optional(&mut *c).await? else {
        return if found { Ok(true) } else { Err(Error::Denied) };
    };
    let fields = qualified_fields(service, c, tenant, target, policy, version).await?;
    found |= fields.contains(&input.field);
    let keys: Vec<_> = fields.into_iter().collect();
    // Both index extremes must match even if the same version occurs thousands of times.
    let differs: bool = sqlx::query_scalar("SELECT
        (SELECT field_set_digest FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2
         AND source=$3 AND epoch=$4 AND policy=$5 AND policy_version=$6 ORDER BY field_set_digest LIMIT 1)
          <> mdm_telemetry.field_set_digest($7::text[]) OR
        (SELECT field_set_digest FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2
         AND source=$3 AND epoch=$4 AND policy=$5 AND policy_version=$6 ORDER BY field_set_digest DESC LIMIT 1)
          <> mdm_telemetry.field_set_digest($7::text[])")
        .bind(tenant.to_string()).bind(input.device.into_uuid()).bind(target.source.as_str())
        .bind(target.epoch).bind(policy).bind(version).bind(keys).fetch_one(&mut *c).await?;
    if differs {
        return Err(Error::Denied);
    }
    if row.is_none() {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3248))")
            .bind(tenant.to_string())
            .execute(&mut *c)
            .await?;
        // An idle tenant may have missed its periodic sweep. Expired checkpoints
        // must not keep a newly admitted identity out of the bounded table.
        prune_checks(c, tenant).await?;
        let full: bool = sqlx::query_scalar(
            "SELECT count(*)>=256 FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid",
        )
        .bind(tenant.to_string())
        .fetch_one(&mut *c)
        .await?;
        if full {
            // A confirmed Blocked step can rebuild its proof. Evict at most one
            // idle proof, leaving its audited request and provider receipt intact.
            let freed=sqlx::query("WITH victim AS (SELECT id FROM mdm_telemetry.stream_checks
                 WHERE tenant_id=$1::uuid AND reclaimable ORDER BY expires_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
                 DELETE FROM mdm_telemetry.stream_checks s USING victim v WHERE s.tenant_id=$1::uuid AND s.id=v.id")
                .bind(tenant.to_string()).execute(&mut *c).await?.rows_affected();
            if freed == 0 {
                return Err(Error::Capacity);
            }
        }
    }
    sqlx::query("INSERT INTO mdm_telemetry.stream_checks(tenant_id,id,binding,device,source,epoch,catalog_revision,byte_limit,policy,version,found,expires_at)
        VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp()+interval '24 hours')
        ON CONFLICT(tenant_id,id) DO UPDATE SET catalog_revision=excluded.catalog_revision,byte_limit=excluded.byte_limit,
          policy=excluded.policy,version=excluded.version,found=excluded.found,expires_at=excluded.expires_at,reclaimable=false")
        .bind(tenant.to_string()).bind(input.id).bind(binding).bind(input.device.into_uuid()).bind(target.source.as_str()).bind(target.epoch)
        .bind(revision).bind(limit).bind(policy).bind(version).bind(found).execute(c).await?;
    Ok(false)
}

pub(super) async fn clear(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    binding: &[u8],
) -> Result<(), Error> {
    sqlx::query(
        "DELETE FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2 AND binding=$3",
    )
    .bind(tenant.to_string())
    .bind(id)
    .bind(binding)
    .execute(c)
    .await?;
    Ok(())
}

async fn qualified_fields(
    service: &Service,
    c: &mut PgConnection,
    tenant: TenantId,
    target: &StreamTarget,
    policy: Uuid,
    version: Uuid,
) -> Result<BTreeSet<String>, Error> {
    let (source, projection, fields) = service
        .policies
        .qualification_on(c, tenant, policy, version)
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Denied)?;
    if source != target.source || fields.is_empty() || fields.len() > 64 {
        return Err(Error::Denied);
    }
    let charge: usize = fields
        .iter()
        .map(|field| field.key.len() + std::mem::size_of::<i64>())
        .sum();
    if charge > service.maintenance_policy.authorization_bytes.get() as usize {
        return Err(Error::Capacity);
    }
    let mut keys = Vec::with_capacity(fields.len());
    let mut versions = Vec::with_capacity(fields.len());
    for field in fields {
        keys.push(field.key);
        versions.push(i64::try_from(field.version).map_err(|_| Error::Denied)?);
    }
    let qualified: bool = sqlx::query_scalar(
        "SELECT bool_and(coalesce(
           d.definition->>'key'=wanted.field
           AND (d.definition->>'version')::bigint=wanted.version
           AND d.definition->>'sensitivity' IN ('standard','sensitive')
           AND (d.definition->'sources') ? $4
           AND ($5 OR jsonb_typeof(d.definition->'timeSeries')='object'),false))
         FROM unnest($2::text[],$3::bigint[]) AS wanted(field,version)
         LEFT JOIN mdm.field_versions d ON (d.tenant_id,d.field,d.version)=($1::uuid,wanted.field,wanted.version)"
    ).bind(tenant.to_string()).bind(&keys).bind(&versions).bind(source.as_str())
    .bind(projection == rss_mdm_resource::TelemetryProjection::Current).fetch_one(c).await?;
    if !qualified {
        return Err(Error::Denied);
    }
    let count = keys.len();
    let keys: BTreeSet<_> = keys.into_iter().collect();
    if keys.len() != count {
        return Err(Error::Denied);
    }
    Ok(keys)
}

/// A quota admission can hold its own expired ID while another admission holds
/// the tenant quota fence. Sweeps never wait for another transaction's row.
pub(crate) async fn prune_checks(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
) -> Result<(), sqlx::Error> {
    sqlx::query("WITH expired AS (SELECT id FROM mdm_telemetry.stream_checks
        WHERE tenant_id=$1::uuid AND expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT 256 FOR UPDATE SKIP LOCKED)
        DELETE FROM mdm_telemetry.stream_checks s USING expired e WHERE s.tenant_id=$1::uuid AND s.id=e.id")
        .bind(tenant.to_string()).execute(c).await?;
    Ok(())
}
