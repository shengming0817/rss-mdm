use rss_mdm_inventory as model;
use rss_observation::{Body, ErrorKind};
use rss_observation_postgres::PgSource;
use rss_projection::{DefinitionIdentity, Event, ProjectionScope};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub fn definition() -> DefinitionIdentity {
    DefinitionIdentity::new(
        Sha256::digest(concat!(
            "inventory-v1:device-basics:1:model-os:utf8-v1:exact-scope:observed-received:",
            include_str!("../migrations/0001_inventory.sql")
        ))
        .into(),
    )
}
/// Inventory effect consumes a source without exposing its internal handle.
/// ```compile_fail
/// fn bypass<C: rss_observation::Clock>(effect: rss_mdm_inventory_postgres::Inventory<C>) {
///     let _ = effect.source;
/// }
/// ```
pub struct Inventory<C: rss_observation::Clock> {
    source: Arc<PgSource<C>>,
}
impl<C: rss_observation::Clock> Inventory<C> {
    pub fn new(source: Arc<PgSource<C>>) -> Self {
        Self { source }
    }
}
impl<C: rss_observation::Clock> PgEffect for Inventory<C> {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        projection: &ProjectionScope,
        event: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        let applicable = self
            .source
            .resolve_in_transaction(tx, event)
            .await
            .map_err(|e| match e.kind() {
                ErrorKind::Storage
                | ErrorKind::Deadline
                | ErrorKind::Closed
                | ErrorKind::CommitUnknown
                | ErrorKind::RollbackFailed => PgOperationError::unavailable(e),
                _ => PgOperationError::rejected(),
            })?;
        let record = applicable.record();
        if record.scope().dataset().as_str() != model::DATASET {
            return Ok(PgEffectOutcome::Filtered);
        }
        model::validate(record.batch()).map_err(|_| PgOperationError::rejected())?;
        let scope = record
            .scope()
            .encode()
            .map_err(|_| PgOperationError::rejected())?;
        let coverage = serde_json::to_string(record.batch().coverage())
            .map_err(|_| PgOperationError::rejected())?;
        let tenant = projection.source().tenant().to_string();
        let journal = projection.source().source().to_owned();
        let generation = projection.generation().to_owned();
        let batch = record.batch().id().as_str().to_owned();
        let observed = record.batch().observed_at_seconds();
        let received =
            i64::try_from(record.received_at()).map_err(|_| PgOperationError::rejected())?;
        let body = record.batch().body().clone();
        tx.with_connection(move |conn| Box::pin(async move {
            if matches!(body, Body::Snapshot(_)) {
                sqlx::query("DELETE FROM mdm.inventory WHERE tenant_id=$1::uuid AND journal=$2 AND generation=$3 AND scope=$4 AND coverage=$5")
                    .bind(&tenant).bind(&journal).bind(&generation).bind(&scope).bind(&coverage).execute(&mut *conn).await?;
            }
            for change in body.changes() {
                if let Some(value) = change.value() {
                    let value = std::str::from_utf8(value).expect("validated utf8");
                    sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,journal,generation,scope,coverage,field) DO UPDATE SET value=excluded.value,batch_id=excluded.batch_id,observed_at=excluded.observed_at,received_at=excluded.received_at")
                        .bind(&tenant).bind(&journal).bind(&generation).bind(&scope).bind(&coverage).bind(change.key().as_str()).bind(value).bind(&batch).bind(observed).bind(received).execute(&mut *conn).await?;
                } else {
                    sqlx::query("DELETE FROM mdm.inventory WHERE tenant_id=$1::uuid AND journal=$2 AND generation=$3 AND scope=$4 AND coverage=$5 AND field=$6")
                        .bind(&tenant).bind(&journal).bind(&generation).bind(&scope).bind(&coverage).bind(change.key().as_str()).execute(&mut *conn).await?;
                }
            }
            Ok(())
        })).await?;
        Ok(PgEffectOutcome::Applied)
    }
}
