//! Frozen selected membership uses the same sparse-history owner as result pages.
use crate::{GroupSources, SourceDecisions, Rejection, DecisionRecord, DecisionValue, InTransaction, storage::{data, stored_shape}};
use rss_mdm_group::OperationId;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
impl GroupSources {
    /// Look up complete frozen dynamic decisions for at most one evaluator page.
    /// Absence is Unknown, never a negative membership proof.
    pub async fn source_decisions_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        objects: &[String],
        max_bytes: usize,
    ) -> InTransaction<SourceDecisions> {
        crate::store::input!(self.check_transaction(tx)?);
        if objects.len() > rss_mdm_group::limits::OBJECTS {
            return Ok(Err(Rejection::InvalidInput));
        }
        let build = crate::store::input!(self.build_in(tx, id).await?);
        if build.receipt.is_none() {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        if build.request.patch.is_some() {
            let bytes:usize = objects.iter().map(|s|s.len()+1024).sum();
            if bytes>max_bytes { return Ok(Err(Rejection::PageBudgetExceeded)); }
            let tenant = tx.tenant_id().to_string();
            let group = build.request.group.to_string();
            let base = build.request.base_calculation;
            let wanted = objects.to_vec();
            let matched:Vec<String>=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar("SELECT object_id FROM (SELECT DISTINCT ON(m.object_id) m.object_id,m.added FROM mdm_group.member_changes m JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE m.tenant_id=$1::uuid AND m.group_id=$2::uuid AND m.object_id=ANY($3) AND ((r.phase='published' AND r.base_calculation<=$4) OR r.id=$5::uuid) ORDER BY m.object_id,m.revision DESC) latest WHERE added")
                    .bind(tenant).bind(group).bind(wanted).bind(base).bind(id.to_string()).fetch_all(c).await
            })).await?;
            let outcomes = objects
                .iter()
                .map(|o| {
                    (
                        o.clone(),
                        if matched.contains(o) {
                            rss_mdm_group::Outcome::Match
                        } else {
                            rss_mdm_group::Outcome::NoMatch
                        },
                    )
                })
                .collect();
            return Ok(Ok(SourceDecisions { outcomes, bytes }));
        }
        let metadata =
            crate::history::metadata(tx, id, None, Some(objects.to_vec()), objects.len(), false)
                .await?;
        let mut bytes = 0usize;
        for row in &metadata {
            bytes = bytes.saturating_add(row.try_get::<i32, _>("bytes")? as usize + 1024);
        }
        if bytes > max_bytes.min(rss_mdm_group::limits::BATCH_BYTES) {
            return Ok(Err(Rejection::PageBudgetExceeded));
        }
        let rows =
            crate::history::selected_rows(tx, id, None, Some(objects.to_vec()), objects.len(), max_bytes)
                .await?;
        let mut result = std::collections::BTreeMap::new();
        for row in rows.0 {
            let object: String = row.try_get("object_id")?;
            let evidence: Vec<u8> = row.try_get("evidence")?;
            crate::storage::document(&evidence, row.try_get("evidence_digest")?)?;
            let record: DecisionRecord = data(serde_json::from_slice(&evidence))?;
            if record.device != object {
                return Err(stored_shape());
            }
            let outcome = match record.decision {
                DecisionValue::Match => rss_mdm_group::Outcome::Match,
                DecisionValue::NoMatch => rss_mdm_group::Outcome::NoMatch,
                _ => rss_mdm_group::Outcome::Unknown(
                    if record
                        .explanations
                        .iter()
                        .any(|e| e.outcome == DecisionValue::Conflict)
                    {
                        rss_mdm_group::UnknownReason::Conflict
                    } else {
                        rss_mdm_group::UnknownReason::Missing
                    },
                ),
            };
            result.insert(object, outcome);
        }
        Ok(Ok(SourceDecisions { outcomes: result, bytes }))
    }
}
