use crate::{
    core,
    storage::{data, stored_shape},
    *,
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use sqlx::Row;
/// Origin of membership evidence, independent of worker scheduling.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOrigin {
    /// A validated stored rule produced the decision.
    Rule,
    /// An authorized explicit membership edit selected the device.
    Manual,
}
/// Closed serialized counterpart of the pure rule outcome.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionValue {
    /// Positive match.
    Match,
    /// Negative match.
    NoMatch,
    /// Unknown overall decision.
    Unknown,
    /// Explicit null predicate input.
    Null,
    /// Missing predicate input.
    Missing,
    /// Deleted predicate input.
    Deleted,
    /// Unsupported predicate input.
    Unsupported,
    /// Conflicting predicate inputs.
    Conflict,
}
/// One leaf decision in the immutable rule's AST.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateDecision {
    /// Canonical AST path.
    pub path: Vec<usize>,
    /// Predicate outcome, retaining the reason for Unknown.
    pub outcome: DecisionValue,
}
/// Provenance only; these timestamps do not define a validity window.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldEvidence {
    /// Referenced dictionary field.
    pub field: String,
    /// Product-resolved source.
    pub source: String,
    /// Immutable fact identity.
    pub snapshot_id: String,
    /// Observation timestamp in UTC seconds.
    pub observed_at: i64,
}
/// One immutable device result; never contains original asset values.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    /// Stable device identity.
    pub device: String,
    /// Rule or explicit manual authority.
    pub origin: DecisionOrigin,
    /// Overall membership decision.
    pub decision: DecisionValue,
    /// Bounded predicate outcomes.
    pub explanations: Vec<PredicateDecision>,
    /// Bounded referenced field provenance.
    pub provenance: Vec<FieldEvidence>,
}
pub(crate) fn manual(device: String) -> DecisionRecord {
    DecisionRecord {
        device,
        origin: DecisionOrigin::Manual,
        decision: DecisionValue::Match,
        explanations: vec![],
        provenance: vec![],
    }
}
pub(crate) fn evaluated(object: core::ObjectEvaluation) -> DecisionRecord {
    DecisionRecord {
        device: object.key.id().into(),
        origin: DecisionOrigin::Rule,
        decision: match object.decision {
            core::Decision::Match => DecisionValue::Match,
            core::Decision::NoMatch => DecisionValue::NoMatch,
            core::Decision::Unknown => DecisionValue::Unknown,
        },
        explanations: object
            .explanations
            .into_iter()
            .map(|e| PredicateDecision {
                path: e.path,
                outcome: match e.outcome {
                    core::Outcome::Match => DecisionValue::Match,
                    core::Outcome::NoMatch => DecisionValue::NoMatch,
                    core::Outcome::Unknown(r) => match r {
                        core::UnknownReason::Null => DecisionValue::Null,
                        core::UnknownReason::Missing => DecisionValue::Missing,
                        core::UnknownReason::Deleted => DecisionValue::Deleted,
                        core::UnknownReason::Unsupported => DecisionValue::Unsupported,
                        core::UnknownReason::Conflict => DecisionValue::Conflict,
                    },
                },
            })
            .collect(),
        provenance: object
            .provenance
            .into_iter()
            .map(|(field, p)| FieldEvidence {
                field,
                source: p.source,
                snapshot_id: p.snapshot_id,
                observed_at: p.observed_at.unix_seconds(),
            })
            .collect(),
    }
}
impl GroupStore {
    /// Read bounded decision evidence from one sealed immutable build. The host
    /// authorizes the owning group and binds its cursor to this build identity.
    pub async fn build_decisions_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        after: Option<String>,
        limit: usize,
    ) -> InTransaction<Vec<DecisionRecord>> {
        crate::store::input!(self.check_transaction(tx)?);
        if !(1..=1000).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let build = crate::store::input!(self.build_in(tx, id).await?);
        if !build.input_sealed {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        let tenant = self.tenant.to_string();
        let metadata=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT object_id,octet_length(evidence) AS bytes FROM mdm_group.member_rows WHERE tenant_id=$1::uuid AND run_id=$2::uuid AND ($3::text IS NULL OR object_id>$3 COLLATE \"C\") ORDER BY object_id LIMIT $4")
                .bind(tenant).bind(id.to_string()).bind(after).bind(limit as i64).fetch_all(c).await
        })).await?;
        let mut selected = Vec::new();
        let mut bytes = 0usize;
        for row in metadata {
            let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
            if bytes + size > 16 * 1024 * 1024 {
                break;
            }
            bytes += size;
            selected.push(row.try_get::<String, _>("object_id")?);
        }
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT object_id,matched,evidence,evidence_digest FROM mdm_group.member_rows WHERE tenant_id=$1::uuid AND run_id=$2::uuid AND object_id=ANY($3) ORDER BY object_id")
                .bind(tenant).bind(id.to_string()).bind(selected).fetch_all(c).await
        })).await?;
        let mut result = Vec::new();
        for row in rows {
            let bytes: Vec<u8> = row.try_get("evidence")?;
            crate::storage::document(&bytes, row.try_get("evidence_digest")?)?;
            let record: DecisionRecord = data(serde_json::from_slice(&bytes))?;
            if record.device != row.try_get::<String, _>("object_id")?
                || (record.decision == DecisionValue::Match) != row.try_get::<bool, _>("matched")?
                || (record.origin == DecisionOrigin::Manual) != build.request.patch.is_some()
            {
                return Err(stored_shape());
            }
            result.push(record);
        }
        Ok(Ok(result))
    }
    /// Read a bounded page of the complete, prepared membership difference.
    pub async fn build_changes_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        after: Option<String>,
        limit: usize,
    ) -> InTransaction<DeltaPage> {
        crate::store::input!(self.check_transaction(tx)?);
        if !(1..=1000).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let build = crate::store::input!(self.build_in(tx, id).await?);
        if !build.ready {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        let tenant = self.tenant.to_string();
        let mut rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT object_id,added FROM mdm_group.member_changes WHERE tenant_id=$1::uuid AND run_id=$2::uuid AND ($3::text IS NULL OR object_id>$3 COLLATE \"C\") ORDER BY object_id LIMIT $4")
                .bind(tenant).bind(id.to_string()).bind(after).bind((limit+1) as i64).fetch_all(c).await
        })).await?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next = if more {
            Some(rows.last().ok_or_else(stored_shape)?.try_get("object_id")?)
        } else {
            None
        };
        let mut added = Vec::new();
        let mut removed = Vec::new();
        for row in rows {
            let id = row.try_get("object_id")?;
            if row.try_get("added")? {
                added.push(id);
            } else {
                removed.push(id);
            }
        }
        Ok(Ok(DeltaPage {
            added,
            removed,
            next,
        }))
    }
}
