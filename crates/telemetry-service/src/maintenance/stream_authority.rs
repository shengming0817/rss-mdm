//! Stream membership is immutable within admitted batches. Keep device intake and catalog
//! publication fenced until the caller finishes this maintenance step.
use super::{Error, Request, Service, StreamTarget};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::collections::BTreeSet;
use uuid::Uuid;

type Cursor = (Uuid, Uuid);
const PAGE: i64 = 16;

pub(super) async fn verify(
    service: &Service,
    c: &mut PgConnection,
    tenant: TenantId,
    input: &Request,
    target: &StreamTarget,
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
        .map_err(|_| Error::Storage)?;
    let mut cursor: Option<Cursor> = None;
    let mut found = false;
    loop {
        let page: Vec<Cursor> = sqlx::query_as(
            "SELECT DISTINCT policy,policy_version FROM mdm_telemetry.batches
             WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND epoch=$4
             AND ($5::uuid IS NULL OR (policy,policy_version)>($5,$6))
             ORDER BY policy,policy_version LIMIT $7",
        )
        .bind(tenant.to_string())
        .bind(input.device.into_uuid())
        .bind(target.source.as_str())
        .bind(target.epoch)
        .bind(cursor.map(|v| v.0))
        .bind(cursor.map(|v| v.1))
        .bind(PAGE)
        .fetch_all(&mut *c)
        .await?;
        let last_page = page.len() < PAGE as usize;
        for (policy, version) in page {
            let fields = qualified_fields(service, c, tenant, target, policy, version).await?;
            found |= fields.contains(&input.field);
            let keys: Vec<_> = fields.into_iter().collect();
            // Compare every admitted batch in this indexed publication range in the database.
            // Frequent repeats of an unchanged profile consume no additional host memory or round trips.
            let differs: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.batches
                WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND epoch=$4
                  AND policy=$5 AND policy_version=$6
                  AND NOT (cardinality(fields)=cardinality($7::text[]) AND fields @> $7 AND fields <@ $7))")
                .bind(tenant.to_string()).bind(input.device.into_uuid()).bind(target.source.as_str())
                .bind(target.epoch).bind(policy).bind(version).bind(&keys).fetch_one(&mut *c).await?;
            if differs {
                return Err(Error::Denied);
            }
            cursor = Some((policy, version));
        }
        if last_page {
            return if found { Ok(()) } else { Err(Error::Denied) };
        }
    }
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
