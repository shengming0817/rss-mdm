//! Stream membership is immutable within admitted batches. Keep device intake and catalog
//! publication fenced until the caller finishes this maintenance step.
use super::{Error, Request, Service, StreamTarget};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::collections::BTreeSet;
use uuid::Uuid;

type Cursor = (Uuid, Uuid);
const PAGE: usize = 16;

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
    let mut cursor = (Uuid::nil(), Uuid::nil());
    let mut found = false;
    loop {
        // Each index seek skips all batches with the previous publication. A long-lived
        // stream with one frozen version costs the same number of seeks as a new stream.
        let mut page: Vec<Cursor> = sqlx::query_as(
            "WITH RECURSIVE publications(policy,version,n) AS (
               (SELECT policy,policy_version,1 FROM mdm_telemetry.batches
                WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND epoch=$4
                  AND (policy,policy_version) >= ($5::uuid,$6::uuid)
                ORDER BY policy,policy_version LIMIT 1)
               UNION ALL
               SELECT next.policy,next.policy_version,p.n+1 FROM publications p
               CROSS JOIN LATERAL (SELECT policy,policy_version FROM mdm_telemetry.batches
                 WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND epoch=$4
                   AND (policy,policy_version)>(p.policy,p.version)
                 ORDER BY policy,policy_version LIMIT 1) next WHERE p.n < $7
             ) SELECT policy,version FROM publications ORDER BY n",
        )
        .bind(tenant.to_string())
        .bind(input.device.into_uuid())
        .bind(target.source.as_str())
        .bind(target.epoch)
        .bind(cursor.0)
        .bind(cursor.1)
        .bind(i32::try_from(PAGE + 1).expect("bounded authorization page"))
        .fetch_all(&mut *c)
        .await?;
        let next = if page.len() > PAGE { page.pop() } else { None };
        for (policy, version) in page {
            let fields = qualified_fields(service, c, tenant, target, policy, version).await?;
            found |= fields.contains(&input.field);
            let keys: Vec<_> = fields.into_iter().collect();
            // An ordered index covers every admission. Equal minimum and maximum prove
            // that every batch matches this frozen version without reading its repetitions.
            let differs: bool = sqlx::query_scalar("SELECT
                (SELECT field_set_digest FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2
                 AND source=$3 AND epoch=$4 AND policy=$5 AND policy_version=$6 ORDER BY field_set_digest LIMIT 1)
                  <> mdm_telemetry.field_set_digest($7::text[]) OR
                (SELECT field_set_digest FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2
                 AND source=$3 AND epoch=$4 AND policy=$5 AND policy_version=$6 ORDER BY field_set_digest DESC LIMIT 1)
                  <> mdm_telemetry.field_set_digest($7::text[])")
                .bind(tenant.to_string()).bind(input.device.into_uuid()).bind(target.source.as_str())
                .bind(target.epoch).bind(policy).bind(version).bind(&keys).fetch_one(&mut *c).await?;
            if differs {
                return Err(Error::Denied);
            }
        }
        match next {
            Some(key) => cursor = key,
            None => return if found { Ok(()) } else { Err(Error::Denied) },
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
