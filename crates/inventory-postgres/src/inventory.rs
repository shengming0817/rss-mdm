use rss_mdm_inventory as model;
use rss_observation::Body;
use rss_observation_postgres::PgSource;
use rss_projection::{DefinitionIdentity, Event, Phase, Position, ProjectionScope};
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
            .map_err(|error| source_error(error, event.position()))?;
        let record = applicable.record();
        if record.scope().dataset().as_str() != model::DATASET {
            return Ok(PgEffectOutcome::Filtered);
        }
        model::validate(record.batch()).map_err(|error| rejected(event.position(), error))?;
        let scope = record
            .scope()
            .encode()
            .map_err(|error| rejected(event.position(), error))?;
        let coverage = serde_json::to_string(record.batch().coverage())
            .map_err(|error| rejected(event.position(), error))?;
        let tenant = projection.source().tenant().to_string();
        let journal = projection.source().source().to_owned();
        let generation = projection.generation().to_owned();
        let batch = record.batch().id().as_str().to_owned();
        let observed = record.batch().observed_at_seconds();
        let received = i64::try_from(record.received_at())
            .map_err(|error| rejected(event.position(), error))?;
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

fn rejected(
    position: Position,
    source: impl std::error::Error + Send + Sync + 'static,
) -> PgOperationError {
    PgOperationError::rejected(Phase::Application, None, Some(position), source)
}

// ref: rss crates/examples/src/observation/model.rs@e1dddb241c2bb015e7a8a71d0881d790d879fe9c
fn source_error(error: rss_projection::Error, event_position: Position) -> PgOperationError {
    use rss_projection::ErrorKind;
    let diagnostic = error.diagnostic();
    let phase = diagnostic.map_or(Phase::Application, |d| d.phase());
    let position = diagnostic
        .and_then(|d| d.position())
        .unwrap_or(event_position);
    let sqlstate = diagnostic.and_then(|d| d.sqlstate()).map(str::to_owned);
    match error.kind() {
        ErrorKind::Unavailable
        | ErrorKind::Deadline
        | ErrorKind::Cancelled
        | ErrorKind::CommitUnknown
        | ErrorKind::RollbackFailed => {
            PgOperationError::unavailable(phase, sqlstate.as_deref(), Some(position), error)
        }
        ErrorKind::InvalidInput
        | ErrorKind::ScopeMismatch
        | ErrorKind::OutOfOrder
        | ErrorKind::SourceContract
        | ErrorKind::Conflict
        | ErrorKind::Fenced
        | ErrorKind::Rejected
        | ErrorKind::StorageContract => {
            PgOperationError::rejected(phase, sqlstate.as_deref(), Some(position), error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_failures_preserve_recovery_and_safe_context() {
        use rss_projection::{Error, ErrorKind};
        let position = Position::new(7).unwrap();
        for (kind, expected) in [
            (ErrorKind::Unavailable, ErrorKind::Unavailable),
            (ErrorKind::Deadline, ErrorKind::Unavailable),
            (ErrorKind::Cancelled, ErrorKind::Unavailable),
            (ErrorKind::StorageContract, ErrorKind::Rejected),
            (ErrorKind::SourceContract, ErrorKind::Rejected),
        ] {
            let source = Error::provider(
                kind,
                Phase::Restore,
                Some("08006"),
                Some(position),
                std::io::Error::other("synthetic-secret"),
            );
            let result = Error::from(source_error(source, Position::new(9).unwrap()));
            assert_eq!(result.kind(), expected);
            let diagnostic = result.diagnostic().unwrap();
            assert_eq!(diagnostic.phase(), Phase::Restore);
            assert_eq!(diagnostic.sqlstate(), Some("08006"));
            assert_eq!(diagnostic.position(), Some(position));
            assert!(!format!("{result:?}").contains("synthetic-secret"));
        }
        let result = Error::from(source_error(ErrorKind::Conflict.into(), position));
        assert_eq!(result.diagnostic().unwrap().position(), Some(position));
    }
}
