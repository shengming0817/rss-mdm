use crate::{
    core,
    storage::{data, stored_shape},
    *,
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use sqlx::Row;
/// Origin of membership evidence, independent of worker scheduling.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOrigin {
    /// A validated stored rule produced the decision.
    Rule,
    /// An authorized explicit membership edit selected the device.
    Manual,
    /// An immutable product lifecycle selector produced the decision.
    System,
}
/// Closed serialized counterpart of the pure rule outcome.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
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
impl From<core::Outcome> for DecisionValue {
    fn from(value: core::Outcome) -> Self {
        match value {
            core::Outcome::Match => Self::Match,
            core::Outcome::NoMatch => Self::NoMatch,
            core::Outcome::Unknown(reason) => match reason {
                core::UnknownReason::Null => Self::Null,
                core::UnknownReason::Missing => Self::Missing,
                core::UnknownReason::Deleted => Self::Deleted,
                core::UnknownReason::Unsupported => Self::Unsupported,
                core::UnknownReason::Conflict => Self::Conflict,
            },
        }
    }
}
/// One leaf decision in the immutable rule's AST.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateDecision {
    /// Context that supplied this complete rule evaluation.
    pub context: String,
    /// Canonical AST path.
    pub path: Vec<usize>,
    /// Predicate outcome, retaining the reason for Unknown.
    pub outcome: DecisionValue,
}
/// Provenance only; these timestamps do not define a validity window.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldEvidence {
    /// Opaque context identity within the evaluated device.
    pub context: String,
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
            .contexts
            .iter()
            .flat_map(|(context, result)| result.explanations.iter().map(move |e| (context, e)))
            .map(|(context, e)| PredicateDecision {
                context: context.clone(),
                path: e.path.clone(),
                outcome: e.outcome.into(),
            })
            .collect(),
        provenance: object
            .contexts
            .into_iter()
            .flat_map(|(context, result)| {
                result
                    .provenance
                    .into_iter()
                    .map(move |(field, p)| (context.clone(), field, p))
            })
            .map(|(context, field, p)| FieldEvidence {
                context,
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
        if !(1..=usize::from(rss_mdm_query::MAX_PAGE_LIMIT) + 1).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let build = crate::store::input!(self.build_in(tx, id).await?);
        if !build.input_sealed {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        if build.request.patch.is_some() {
            let devices = crate::store::input!(self.build_members_in(tx, id, after, limit).await?);
            return Ok(Ok(devices.into_iter().map(manual).collect()));
        }
        let rows = crate::history::rows(tx, id, after, limit).await?;
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
    /// Look up complete frozen dynamic decisions for at most one evaluator page.
    /// Absence is Unknown, never a negative membership proof.
    pub async fn source_decisions_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        objects: &[String],
    ) -> InTransaction<std::collections::BTreeMap<String, core::Outcome>> {
        crate::store::input!(self.check_transaction(tx)?);
        if objects.len() > core::limits::OBJECTS {
            return Ok(Err(Rejection::InvalidInput));
        }
        let build = crate::store::input!(self.build_in(tx, id).await?);
        if build.receipt.is_none() {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        if build.request.patch.is_some() {
            let tenant = self.tenant.to_string();
            let group = build.request.group.to_string();
            let base = build.request.base_calculation;
            let wanted = objects.to_vec();
            let matched:Vec<String>=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar("SELECT object_id FROM (SELECT DISTINCT ON(m.object_id) m.object_id,m.added FROM mdm_group.member_changes m JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE m.tenant_id=$1::uuid AND m.group_id=$2::uuid AND m.object_id=ANY($3) AND ((r.phase='published' AND r.base_calculation<=$4) OR r.id=$5::uuid) ORDER BY m.object_id,m.revision DESC) latest WHERE added")
                    .bind(tenant).bind(group).bind(wanted).bind(base).bind(id.to_string()).fetch_all(c).await
            })).await?;
            return Ok(Ok(objects
                .iter()
                .map(|o| {
                    (
                        o.clone(),
                        if matched.contains(o) {
                            core::Outcome::Match
                        } else {
                            core::Outcome::NoMatch
                        },
                    )
                })
                .collect()));
        }
        let metadata =
            crate::history::metadata(tx, id, None, Some(objects.to_vec()), objects.len(), false)
                .await?;
        let mut bytes = 0usize;
        for row in &metadata {
            bytes = bytes.saturating_add(row.try_get::<i32, _>("bytes")? as usize + 1024);
        }
        if bytes > core::limits::BATCH_BYTES {
            return Ok(Err(Rejection::PageBudgetExceeded));
        }
        let rows =
            crate::history::selected_rows(tx, id, None, Some(objects.to_vec()), objects.len())
                .await?;
        let mut result = std::collections::BTreeMap::new();
        for row in rows {
            let object: String = row.try_get("object_id")?;
            let evidence: Vec<u8> = row.try_get("evidence")?;
            crate::storage::document(&evidence, row.try_get("evidence_digest")?)?;
            let record: DecisionRecord = data(serde_json::from_slice(&evidence))?;
            if record.device != object {
                return Err(stored_shape());
            }
            let outcome = match record.decision {
                DecisionValue::Match => core::Outcome::Match,
                DecisionValue::NoMatch => core::Outcome::NoMatch,
                _ => core::Outcome::Unknown(
                    if record
                        .explanations
                        .iter()
                        .any(|e| e.outcome == DecisionValue::Conflict)
                    {
                        core::UnknownReason::Conflict
                    } else {
                        core::UnknownReason::Missing
                    },
                ),
            };
            result.insert(object, outcome);
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
