use super::*;
use crate::reports::AssetFacts;
use rss_mdm_agent_wire::da;
use rss_observation_postgres::VerifiedObservation;
use rss_projection::{EventWith, Phase};
use rss_projection_postgres::{
    EffectIsolation, PgEffect, PgEffectOutcome, PgOperationError, PgTransaction,
};

pub(super) struct Assets {
    pub source: Arc<Source>,
    pub binding: ExecutionBinding,
    pub installation: Uuid,
}
fn facts(kind: &str, bytes: &[u8]) -> Result<(da::ReportIdentity, i64, AssetFacts), Error> {
    match kind {
        "status" => {
            let r: da::StatusReport = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
            r.validate().map_err(|_| Error::Corrupt)?;
            Ok((
                r.identity,
                r.sequence,
                AssetFacts::Status {
                    client_version: r.client_version,
                    modules: r.modules,
                    health: r.health,
                    binding: r.binding,
                    factor: r.factor,
                    configuration_digest: r.configuration_digest,
                },
            ))
        }
        "application" => {
            let r: da::ApplicationReport =
                serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
            r.validate().map_err(|_| Error::Corrupt)?;
            Ok((
                r.identity,
                r.sequence,
                AssetFacts::Application {
                    artifact: r.artifact,
                    digest: r.digest,
                    state: r.state,
                    sources: r.sources,
                    operation_id: r.operation_id,
                },
            ))
        }
        _ => Err(Error::Corrupt),
    }
}
impl PgEffect for Assets {
    type Item = EventWith<VerifiedObservation>;
    const ISOLATION: EffectIsolation = EffectIsolation::ReadCommitted;
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        projection: &ProjectionScope,
        item: &Self::Item,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        let pos = item.as_ref().position();
        let rejected = |e| PgOperationError::rejected(Phase::Application, None, Some(pos), e);
        if tx.tenant() != self.binding.tenant()
            || projection.source() != self.source.scope()
            || projection.generation() != GENERATION
        {
            return Err(rejected(Error::Forbidden));
        }
        let checked = self
            .source
            .resolve_in_transaction(tx, item)
            .await
            .map_err(|e| match e.kind() {
                rss_projection::ErrorKind::HistoryExpired => {
                    PgOperationError::history_expired(Some(pos), e)
                }
                rss_projection::ErrorKind::Unavailable
                | rss_projection::ErrorKind::Deadline
                | rss_projection::ErrorKind::Cancelled => {
                    PgOperationError::unavailable(Phase::Restore, None, Some(pos), e)
                }
                _ => PgOperationError::rejected(Phase::Restore, None, Some(pos), e),
            })?;
        let record = checked.record();
        let scope = record.scope();
        let kind = scope.dataset().as_str().to_owned();
        let batch = record.batch();
        let rss_observation::Body::Snapshot(changes) = batch.body() else {
            return Err(rejected(Error::Corrupt));
        };
        let [change] = changes.as_slice() else {
            return Err(rejected(Error::Corrupt));
        };
        let (identity, sequence, values) = facts(
            &kind,
            change.value().ok_or_else(|| rejected(Error::Corrupt))?,
        )
        .map_err(rejected)?;
        let epoch =
            Uuid::parse_str(scope.registration().as_str()).map_err(|_| rejected(Error::Corrupt))?;
        let device = identity.device_id.into_uuid();
        let expected = delivery::scope(
            self.binding.tenant(),
            self.installation,
            device,
            epoch,
            &kind,
        )
        .map_err(|_| rejected(Error::Corrupt))?;
        if scope != &expected
            || identity.tenant.to_string() != self.binding.tenant().to_string()
            || identity.service_id != self.installation
            || sequence as u64 != batch.sequence()
            || change.key().as_str() != "report"
            || batch.id().as_str() != sequence.to_string()
        {
            return Err(rejected(Error::Corrupt));
        }
        let binding = self.binding;
        let received = batch.observed_at_seconds();
        tx.with_connection(move |c|Box::pin(async move{
            fence(c,binding).await?;
            sqlx::query("INSERT INTO rss_da.inventory_assets (tenant_id,installation,device,registration_epoch,kind,generation,sequence,position,received_at,facts) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (tenant_id,installation,device,registration_epoch,kind,generation) DO UPDATE SET sequence=excluded.sequence,position=excluded.position,received_at=excluded.received_at,facts=excluded.facts")
              .bind(identity.tenant).bind(identity.service_id).bind(device).bind(epoch).bind(kind).bind(GENERATION).bind(sequence).bind(pos.get() as i64).bind(received).bind(sqlx::types::Json(values)).execute(c).await?;
            Ok(())
        })).await?;
        Ok(PgEffectOutcome::Applied)
    }
}
