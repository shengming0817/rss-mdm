use rss_mdm_inventory as model;
use rss_observation::Body;
use rss_observation_postgres::PgSource;
use rss_projection::{DefinitionIdentity, Event, Phase, Position, ProjectionScope};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const JOURNAL: &str = "mdm.observation.v1";
const PROJECTION: &str = "inventory";
const GENERATION: &str = "inventory-projection-v1";

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
    digest.update(":registered-collection:typed-fields-v1:exact-scope:observed-received:");
    digest.update(crate::MIGRATION_SQL);
    DefinitionIdentity::new(digest.finalize().into())
}
/// Inventory effect consumes a source without exposing its internal handle.
/// Applies only the canonical tenant projection scope; other datasets are filtered.
/// Snapshot batches replace only fields selected by the frozen definition within
/// the exact tenant/journal/generation/scope; deltas upsert or delete individual fields. Source and model
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
        let tenant = projection.source().tenant();
        tx.with_connection(move |c| {
            Box::pin(async move { crate::lock_watermark_in(c, tenant).await.map(|_| ()) })
        })
        .await?;
        let applicable = self
            .source
            .resolve_in_transaction(tx, event)
            .await
            .map_err(|error| source_error(error, event.position()))?;
        let record = applicable.record();
        let tenant = projection.source().tenant();
        let source = model::Source::parse(record.scope().source().as_str())
            .map_err(|e| rejected(event.position(), e))?;
        let coverage = serde_json::to_string(record.batch().coverage())
            .map_err(|e| rejected(event.position(), e))?;
        let expected = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::collection_in(c, tenant, source, &coverage)
                        .await
                        .map_err(|_| {
                            sqlx::Error::Protocol("unregistered inventory collection".into())
                        })
                })
            })
            .await?;
        expected
            .validate_scope(record.scope())
            .map_err(|e| rejected(event.position(), e))?;
        let report_scope = record.scope().clone();
        let report_batch = record.batch().clone();
        let frozen = expected.clone();
        let progress = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::collection_result_in(c, &report_scope, &report_batch, &frozen)
                        .await
                        .map_err(|_| {
                            sqlx::Error::Protocol("invalid collection result reference".into())
                        })
                })
            })
            .await?;
        let scope = record
            .scope()
            .encode()
            .map_err(|error| rejected(event.position(), error))?;
        let coverage = serde_json::to_string(record.batch().coverage())
            .map_err(|error| rejected(event.position(), error))?;
        let tenant_id = projection.source().tenant();
        let tenant = tenant_id.to_string();
        let journal = projection.source().source().to_owned();
        let generation = projection.generation().to_owned();
        let batch = record.batch().id().as_str().to_owned();
        let observed = record.batch().observed_at_seconds();
        let received = i64::try_from(record.received_at())
            .map_err(|error| rejected(event.position(), error))?;
        let sequence = i64::try_from(record.batch().sequence())
            .map_err(|error| rejected(event.position(), error))?;
        let fields: Vec<_> = expected.fields().map(|f| f.key).collect();
        let body = progress
            .body()
            .map_err(|e| rejected(event.position(), e))?
            .ok_or_else(|| rejected(event.position(), rss_projection::ErrorKind::SourceContract))?;
        let registration = record.scope().registration().as_str().to_owned();
        let source = record.scope().source().as_str().to_owned();
        let epoch = record.scope().epoch().as_str().to_owned();
        tx.with_connection(move |conn| Box::pin(async move {
            let mut changes=body.changes().to_vec();
            if matches!(body,Body::Snapshot(_)) {
                for field in &fields {
                    if !changes.iter().any(|c|c.key().as_str()==field.as_str()) {changes.push(rss_observation::Change::delete(rss_observation::Id::new(field.as_str()).expect("validated field")));}
                }
            }
            for change in &changes {
                let field=model::FieldKey::parse(change.key().as_str()).expect("validated field");
                let field_scope=expected.field_scope(field).expect("validated field").canonical().map_err(|_|sqlx::Error::Protocol("invalid field scope".into()))?;
                let outcome=change.value().map(|v|model::CollectedValue::decode(expected.field(field).expect("validated field"),v).expect("validated collected outcome"));
                let mut array=None;
                let (state,value)=match &outcome {Some(model::CollectedValue::Value(v))=>{let definition=expected.field(field).expect("validated field");let canonical=definition.canonical_value(v.clone()).map_err(|_|sqlx::Error::Protocol("invalid asset value".into()))?;
                    if let model::Scalar::Array(values)=&canonical {array=Some(crate::arrays::prepare(definition,values).map_err(crate::arrays::storage_error)?);("known",None)}
                    else {("known",Some(serde_json::to_string(&canonical).expect("scalar encoding"))) }},Some(model::CollectedValue::Unknown { reason })=>(match reason { model::UnknownReason::UnorderedConflict=>"unknown_conflict", model::UnknownReason::Incomplete=>"unknown_incomplete", model::UnknownReason::NativeStatus=>"unknown_native", model::UnknownReason::EvidenceLimit=>"unknown_limit" },None),Some(model::CollectedValue::Null)=>("null",None),Some(model::CollectedValue::Deleted)=>("deleted",None),Some(model::CollectedValue::Unsupported)=>("unsupported",None),None=>("deleted",None)};
                let changed=sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence,field_scope,value_version,last_known_version) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$7,CASE WHEN $11='known' THEN $8 END,CASE WHEN $11='known' THEN $9 END,CASE WHEN $11='known' THEN $10 END,$12,$13,$14,$15,$16,$17,$17) ON CONFLICT(tenant_id,journal,generation,scope,field,field_scope) DO UPDATE SET coverage=excluded.coverage,collection_sequence=excluded.collection_sequence,value=excluded.value,value_version=excluded.value_version,state=excluded.state,batch_id=excluded.batch_id,observed_at=excluded.observed_at,received_at=excluded.received_at,last_known=CASE WHEN excluded.state='known' THEN excluded.value ELSE mdm.inventory.last_known END,last_known_version=CASE WHEN excluded.state='known' THEN excluded.value_version ELSE mdm.inventory.last_known_version END,last_known_batch=CASE WHEN excluded.state='known' THEN excluded.batch_id ELSE mdm.inventory.last_known_batch END,last_known_observed=CASE WHEN excluded.state='known' THEN excluded.observed_at ELSE mdm.inventory.last_known_observed END,last_known_received=CASE WHEN excluded.state='known' THEN excluded.received_at ELSE mdm.inventory.last_known_received END WHERE mdm.inventory.collection_sequence<=excluded.collection_sequence")
                    .bind(&tenant).bind(&journal).bind(&generation).bind(&scope).bind(&coverage).bind(change.key().as_str()).bind(value).bind(&batch).bind(observed).bind(received).bind(state).bind(&registration).bind(&source).bind(&epoch).bind(sequence).bind(&field_scope).bind(array.as_ref().map(|a|&a.metadata.version)).execute(&mut *conn).await?.rows_affected();
                if changed>0 && let Some(array)=array {crate::arrays::store(conn,tenant_id,&array).await.map_err(crate::arrays::storage_error)?;}
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
        assert_eq!(
            projection_scope(tenant).generation(),
            "inventory-projection-v1"
        );
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
