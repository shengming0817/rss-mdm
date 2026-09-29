//! Agent report intake shares the registration transaction and owns collection writes.
use crate::{Error, Failure, database::db, device::DevicePrincipal};
use rss_mdm_inventory::ReportSource as InventorySource;
use rss_observation::{Batch, Scope};
use sqlx::Row;
const MAX_PENDING_REPORTS_PER_REGISTRATION: i64 = 32;
pub async fn accept_in(
    tx: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
    scope: &Scope,
    batch: &Batch,
) -> Result<(i64, bool), Error> {
    let digest = batch
        .fingerprint(scope)
        .map_err(|_| Error::Malformed)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let live_scope =
        crate::device::store::revalidate_source(tx, principal, InventorySource::AgentBuiltin)
            .await?;
    if &live_scope != scope {
        return Err(Error::Unauthorized);
    }
    // V1 report ids are tenant-global. This lock covers the absent-row case across registrations;
    // revalidate_source already holds the channel lock that serializes capacity and retention.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2467))")
        .bind(format!("{}:{}", principal.tenant(), batch.id().as_str()))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if let Some(row) = sqlx::query("SELECT registration::text,source,epoch::text,digest,sealed_at FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR SHARE")
        .bind(principal.tenant().to_string()).bind(batch.id().as_str().to_string()).fetch_optional(&mut *tx).await.map_err(db)? {
        if row.try_get::<String, _>("registration").map_err(db)? != principal.registration().to_string()
            || row.try_get::<String, _>("source").map_err(db)? != InventorySource::AgentBuiltin.as_str()
            || row.try_get::<String, _>("epoch").map_err(db)? != scope.epoch().as_str()
            || row.try_get::<String, _>("digest").map_err(db)? != digest {
            return Err(Error::Conflict);
        }
        return Ok((row.try_get("sealed_at").map_err(db)?, false));
    }
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source='agent.builtin' AND epoch=$3::uuid AND delivery_pending")
        .bind(principal.tenant().to_string()).bind(principal.registration().to_string()).bind(scope.epoch().as_str()).fetch_one(&mut *tx).await.map_err(db)?;
    if pending >= MAX_PENDING_REPORTS_PER_REGISTRATION {
        return Err(Error::Unavailable(Failure::Capacity));
    }
    let _: i64 = sqlx::query_scalar("SELECT mdm_access.prune_agent_collections($1::uuid,$2::uuid)")
        .bind(principal.registration().to_string())
        .bind(scope.epoch().as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    let received_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
    let result = match batch.body() {
        rss_observation::Body::Snapshot(_) => "snapshot",
        rss_observation::Body::Partial(_) => "partial",
        rss_observation::Body::Failed { .. } => "failed",
        _ => return Err(Error::Malformed),
    };
    let attempts = crate::collection::Attempts::reported(batch.body(), received_at)?;
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) VALUES($1::uuid,$4::uuid,$2::uuid,'agent.builtin',$3::uuid,$6,$5,$9,$11,$10,'complete',$7,$8,$9,true)")
        .bind(principal.tenant().to_string()).bind(principal.registration().to_string()).bind(scope.epoch().as_str()).bind(batch.id().as_str().to_string())
        .bind(i64::try_from(batch.sequence()).map_err(|_| Error::Malformed)?).bind(scope.encode().map_err(|_| Error::Malformed)?)
        .bind(batch.encode()).bind(&digest).bind(received_at).bind(result)
        .bind(serde_json::to_string(&attempts).expect("closed attempts")).execute(&mut *tx).await.map_err(db)?;
    crate::wake::notify(tx).await.map_err(db)?;
    Ok((received_at, true))
}
