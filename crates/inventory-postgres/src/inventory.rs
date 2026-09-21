use rss_mdm_inventory as model;
use rss_observation::Body;
use rss_observation_postgres::PgSource;
use rss_projection::{DefinitionIdentity, Event, Phase, Position, ProjectionScope};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const JOURNAL: &str = "mdm.observation.v1";
const PROJECTION: &str = "inventory";
const GENERATION: &str = "inventory-v2";

/// The product's canonical journal and read-model generation, shared by writer and reader.
pub fn projection_scope(tenant: rss_request_context::TenantId) -> ProjectionScope {
    ProjectionScope::new(
        rss_projection::SourceScope::new(tenant, JOURNAL).expect("static inventory journal"),
        PROJECTION,
        GENERATION,
    )
    .expect("static inventory projection")
}
/// Return the deterministic projection definition digest binding generation, field semantics
/// and the initial migration bytes. Performs no schema inspection or migration.
pub fn definition() -> DefinitionIdentity {
    let mut digest = Sha256::new();
    digest.update(GENERATION);
    digest.update(":device-basics:2:model-os:typed-v2:exact-scope:observed-received:");
    digest.update(include_str!("../migrations/0001_inventory.sql"));
    digest.update(include_str!("../migrations/0003_assets.sql"));
    DefinitionIdentity::new(digest.finalize().into())
}
/// Inventory effect consumes a source without exposing its internal handle.
/// Applies only the canonical tenant projection scope; other datasets are filtered.
/// Snapshot batches replace rows within the exact tenant/journal/generation/scope/
/// coverage, while deltas upsert or delete individual fields. Source and model
/// validation occur before writes. Writes use the supplied projection transaction;
/// the owner controls commit/rollback and checkpoint recovery. A callback result
/// does not prove commit, and cancellation/provider failure does not prove rollback.
/// ```compile_fail
/// fn bypass<C: rss_observation::Clock>(effect: rss_mdm_inventory_postgres::Inventory<C>) {
///     let _ = effect.source;
/// }
/// ```
pub struct Inventory<C: rss_observation::Clock> {
    source: Arc<PgSource<C>>,
}
impl<C: rss_observation::Clock> Inventory<C> {
    /// Bind the caller-owned Observation source without I/O or spawning tasks.
    /// The host must supply its correctly configured runtime, schema and admission checks.
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
        if projection != &projection_scope(projection.source().tenant()) {
            return Err(rejected(
                event.position(),
                rss_projection::ErrorKind::ScopeMismatch,
            ));
        }
        let applicable = self
            .source
            .resolve_in_transaction(tx, event)
            .await
            .map_err(|error| source_error(error, event.position()))?;
        let record = applicable.record();
        if record.scope().dataset().as_str() != model::DATASET {
            return Ok(PgEffectOutcome::Filtered);
        }
        model::ReportSource::parse(record.scope().source().as_str())
            .map_err(|error| rejected(event.position(), error))?;
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
        let registration = record.scope().registration().as_str().to_owned();
        let source = record.scope().source().as_str().to_owned();
        let epoch = record.scope().epoch().as_str().to_owned();
        tx.with_connection(move |conn| Box::pin(async move {
            if matches!(body, Body::Snapshot(_)) {
                sqlx::query("UPDATE mdm.inventory SET state='deleted',value=NULL,batch_id=$6,observed_at=$7,received_at=$8 WHERE tenant_id=$1::uuid AND journal=$2 AND generation=$3 AND scope=$4 AND coverage=$5")
                    .bind(&tenant).bind(&journal).bind(&generation).bind(&scope).bind(&coverage).bind(&batch).bind(observed).bind(received).execute(&mut *conn).await?;
            }
            for change in body.changes() {
                let field=model::FieldKey::parse(change.key().as_str()).expect("validated field");
                let outcome=change.value().map(|v|model::CollectedValue::decode(field,v).expect("validated collected outcome"));
                let (state,value)=match &outcome {Some(model::CollectedValue::Known(s))=>("known",Some(s.as_str())),Some(model::CollectedValue::Unsupported)=>("unsupported",None),None=>("deleted",None)};
                sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$7,CASE WHEN $7 IS NOT NULL THEN $8 END,CASE WHEN $7 IS NOT NULL THEN $9 END,CASE WHEN $7 IS NOT NULL THEN $10 END,$12,$13,$14) ON CONFLICT(tenant_id,journal,generation,scope,coverage,field) DO UPDATE SET value=excluded.value,state=excluded.state,batch_id=excluded.batch_id,observed_at=excluded.observed_at,received_at=excluded.received_at,last_known=coalesce(excluded.value,mdm.inventory.last_known),last_known_batch=CASE WHEN excluded.value IS NOT NULL THEN excluded.batch_id ELSE mdm.inventory.last_known_batch END,last_known_observed=CASE WHEN excluded.value IS NOT NULL THEN excluded.observed_at ELSE mdm.inventory.last_known_observed END,last_known_received=CASE WHEN excluded.value IS NOT NULL THEN excluded.received_at ELSE mdm.inventory.last_known_received END")
                    .bind(&tenant).bind(&journal).bind(&generation).bind(&scope).bind(&coverage).bind(change.key().as_str()).bind(value).bind(&batch).bind(observed).bind(received).bind(state).bind(&registration).bind(&source).bind(&epoch).execute(&mut *conn).await?;
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
    fn canonical_scope_binds_the_current_definition() {
        let tenant =
            rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        assert_eq!(projection_scope(tenant).generation(), "inventory-v2");
        assert_ne!(definition().as_bytes(), &[0; 32]);
    }
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
