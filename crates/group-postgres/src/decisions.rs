use crate::{
    storage::{data, stored_shape},
    *,
};
use rss_mdm_group::OperationId;
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
impl From<rss_mdm_group::Outcome> for DecisionValue {
    fn from(value: rss_mdm_group::Outcome) -> Self {
        match value {
            rss_mdm_group::Outcome::Match => Self::Match,
            rss_mdm_group::Outcome::NoMatch => Self::NoMatch,
            rss_mdm_group::Outcome::Unknown(reason) => match reason {
                rss_mdm_group::UnknownReason::Null => Self::Null,
                rss_mdm_group::UnknownReason::Missing => Self::Missing,
                rss_mdm_group::UnknownReason::Deleted => Self::Deleted,
                rss_mdm_group::UnknownReason::Unsupported => Self::Unsupported,
                rss_mdm_group::UnknownReason::Conflict => Self::Conflict,
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
pub(crate) fn evaluated(object: rss_mdm_group::ObjectEvaluation) -> DecisionRecord {
    DecisionRecord {
        device: object.key.id().into(),
        origin: DecisionOrigin::Rule,
        decision: match object.decision {
            rss_mdm_group::Decision::Match => DecisionValue::Match,
            rss_mdm_group::Decision::NoMatch => DecisionValue::NoMatch,
            rss_mdm_group::Decision::Unknown => DecisionValue::Unknown,
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
        max_bytes: usize,
    ) -> InTransaction<DecisionPage> {
        self.sources.build_decisions_in(tx, id, after, limit, max_bytes).await
    }
    /// Look up frozen decisions within the caller's remaining decoded-byte budget.
    pub async fn source_decisions_in(
        &self, tx: &mut PgTransaction<'_>, id: OperationId,
        objects: &[String], max_bytes: usize,
    ) -> InTransaction<SourceDecisions> {
        self.sources.source_decisions_in(tx, id, objects, max_bytes).await
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
