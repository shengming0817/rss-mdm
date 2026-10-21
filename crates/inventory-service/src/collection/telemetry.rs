//! Authorized periodic observations enter the existing collection delivery owner.
use crate::{Error, database::db};
use rss_mdm_inventory::{CollectionDefinition, CollectionProgress};
use rss_observation::{Batch, Body, Scope};
use sqlx::Row;
use uuid::Uuid;
/// Caller retains the validated registration/source and Policy fences through commit.
/// No new sequence is allocated: historical retransmission preserves producer ordering.
pub async fn accept_on(
    c: &mut sqlx::PgConnection,
    scope: &Scope,
    definition: &CollectionDefinition,
    batch: &Batch,
    received_at: i64,
) -> Result<(), Error> {
    definition
        .validate_scope(scope)
        .map_err(|_| Error::Malformed)?;
    definition.validate(batch).map_err(|_| Error::Malformed)?;
    let id = Uuid::parse_str(batch.id().as_str()).map_err(|_| Error::Malformed)?;
    let registration =
        Uuid::parse_str(scope.registration().as_str()).map_err(|_| Error::Malformed)?;
    let digest = super::store::fingerprint(batch, scope)?;
    let old = sqlx::query("SELECT input_digest,scope FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(scope.tenant().to_string()).bind(id).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(old) = old {
        if old
            .try_get::<Option<String>, _>("input_digest")
            .map_err(db)?
            .as_deref()
            != Some(&digest)
            || old.try_get::<String, _>("scope").map_err(db)?
                != scope.encode().map_err(|_| Error::Malformed)?
        {
            return Err(Error::Conflict);
        }
        return Ok(());
    }
    rss_mdm_inventory_postgres::register_collection_in(c, scope.tenant(), definition)
        .await
        .map_err(|_| Error::Malformed)?;
    let progress = CollectionProgress::reported(definition.clone(), batch.body(), received_at)
        .map_err(|_| Error::Malformed)?;
    let stored = rss_mdm_inventory_postgres::seal_collection_in(
        c,
        rss_mdm_inventory_postgres::CollectionCompletion {
            scope,
            run: batch.id().as_str(),
            sequence: batch.sequence(),
            observed_at: batch.observed_at_seconds(),
            progress: &progress,
        },
    )
    .await
    .map_err(|_| Error::Malformed)?;
    let stored_digest = super::store::fingerprint(&stored, scope)?;
    let result = match stored.body() {
        Body::Snapshot(_) => "snapshot",
        Body::Partial(_) => "partial",
        _ => "failed",
    };
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,reason,batch,digest,input_digest,sealed_at,delivery_pending) VALUES($1::uuid,$2,$3,$4,$5::uuid,$6,$7,$8,$9,$10,'complete',$11,$12,$13,$8,true)")
        .bind(scope.tenant().to_string()).bind(id).bind(registration).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(scope.encode().map_err(|_|Error::Malformed)?)
        .bind(i64::try_from(batch.sequence()).map_err(|_|Error::Malformed)?).bind(received_at).bind(serde_json::to_string(&progress).map_err(|_|Error::Malformed)?)
        .bind(result).bind(stored.encode()).bind(stored_digest).bind(digest).execute(&mut *c).await.map_err(db)?;
    crate::wake::notify(c).await.map_err(db)?;
    Ok(())
}
