//! Device-authorized progress across every collection source; no new execution owner.
use super::*;
use sqlx::Row;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunView {
    pub id: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub source: rss_mdm_inventory::Source,
    pub dataset: String,
    pub template_version: String,
    pub sequence: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub result: crate::collection::RunResult,
    pub reason: Option<crate::collection::FinishReason>,
    pub delivery_pending: bool,
    pub fields: Vec<QualityField>,
}
impl AssetService {
    pub(super) async fn collection_run(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        id: Uuid,
        scope: &ReadScope,
    ) -> Result<RunView> {
        if scope
            .devices
            .as_ref()
            .is_some_and(|ids| !ids.contains(device))
        {
            return Err(Error::Forbidden.into());
        }
        let tenant = self.tenant;
        let device = device.to_owned();
        let row=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT c.registration,r.generation,c.source,c.sequence,c.started_at,c.sealed_at,c.result,c.reason,c.delivery_pending,c.attempts FROM mdm_access.collection_runs c JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(c.tenant_id,c.registration) WHERE c.tenant_id=$1::uuid AND c.id=$2 AND r.device=$3")
                .bind(tenant.to_string()).bind(id).bind(device).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        let progress: rss_mdm_inventory::CollectionProgress =
            stored(serde_json::from_str(row.try_get("attempts")?))?;
        let definition = progress.definition();
        let fields = progress
            .fields()
            .iter()
            .filter(|(key, _)| {
                scope.sensitive
                    || definition
                        .field(**key)
                        .is_ok_and(|f| f.sensitivity == rss_mdm_inventory::Sensitivity::Standard)
            })
            .map(|(key, attempt)| QualityField {
                field: *key,
                quality: attempt.quality,
                status: attempt.status,
                received_at: attempt.received_at,
            })
            .collect();
        Ok(RunView {
            id,
            registration: row.try_get("registration")?,
            generation: row.try_get("generation")?,
            source: stored(rss_mdm_inventory::Source::parse(row.try_get("source")?))?,
            dataset: definition.dataset().into(),
            template_version: definition.version().into(),
            sequence: row.try_get("sequence")?,
            started_at: row.try_get("started_at")?,
            finished_at: row.try_get("sealed_at")?,
            result: crate::collection::RunResult::parse(row.try_get("result")?)?,
            reason: row
                .try_get::<Option<String>, _>("reason")?
                .as_deref()
                .map(crate::collection::FinishReason::parse)
                .transpose()?,
            delivery_pending: row.try_get("delivery_pending")?,
            fields,
        })
    }
}
