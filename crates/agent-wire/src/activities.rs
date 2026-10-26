//! Device-visible management history. Reading these facts never starts an operation.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Exact links to the existing business owners; absent links are not inferred.
#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityLinks {
    /// Policy identity.
    pub policy: Option<Uuid>,
    /// Immutable Policy execution version.
    pub version: Option<Uuid>,
    /// Explicit event batch.
    pub batch: Option<Uuid>,
    /// Exact batch member.
    pub member: Option<Uuid>,
    /// Original request identity.
    pub request: Option<Uuid>,
    /// Native operation identity.
    pub operation: Option<Uuid>,
    /// Action Run identity.
    pub task: Option<Uuid>,
    /// Concrete attempt, qualifying every step reference.
    pub attempt: Option<Uuid>,
    /// Definition step identities within the exact task and attempt.
    pub steps: Vec<String>,
    /// Child operations accepted by the exact batch member.
    pub operations: Vec<crate::runtime::PolicyEventOperation>,
}
/// Registration coordinates of the original producer fact.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityTarget {
    /// Authorized endpoint identity, which can differ between paired channels.
    pub device: String,
    /// Exact registration identity.
    pub registration: Uuid,
    /// Exact registration generation.
    pub generation: i64,
}
/// Allowlisted device activity. Contains no principal, OS identity, names or raw output.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagementActivity {
    /// Stable source-qualified identity, also used to deduplicate incremental delivery.
    pub id: String,
    /// Business source identity.
    pub source: String,
    /// Product activity category.
    pub kind: String,
    /// Actual recorded stage, independent of the current operation status.
    pub phase: String,
    /// Server recording time in UTC Unix seconds.
    pub recorded_at: i64,
    /// Producer observation time in UTC Unix seconds.
    pub observed_at: i64,
    /// Human, AI, Policy or system origin; never a grant.
    pub origin: String,
    /// Original target; Policy parent facts have no device target.
    pub target: Option<ActivityTarget>,
    /// Exact producer coordinates with no user identity.
    pub links: ActivityLinks,
    /// Delivery evidence, independent of execution.
    pub delivery: Option<String>,
    /// Execution evidence, independent of verified effect.
    pub execution: Option<String>,
    /// Qualified effect evidence, absent when unavailable.
    pub effect: Option<String>,
    /// Server receipt/partial reporting evidence, not local cache freshness.
    pub reporting: Option<String>,
    /// Business admission or cancellation decision.
    pub decision: Option<String>,
    /// Audit transaction outcome, never device-effect proof.
    pub audit_outcome: String,
}
/// Scope-local completeness. An observation is not a global source commit fence.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityCoverage {
    /// Source family covered by this observation.
    pub source: String,
    /// Whether all visible committed facts in the observed source snapshot were projected.
    pub complete: bool,
    /// Explicit incomplete/unsupported association or source reasons.
    pub reasons: Vec<String>,
}
/// Snapshot history page or incremental page from the same authorized activity projection.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagementActivityPage {
    /// Bounded allowlisted activity facts.
    pub items: Vec<ManagementActivity>,
    /// Continuation of this fixed snapshot, absent at its end.
    pub next_cursor: Option<String>,
    /// Start incremental reads after this snapshot once all its pages are consumed.
    pub sync_cursor: String,
    /// Server observation time; offline consumers must retain this freshness marker.
    pub as_of: i64,
    /// Coverage only for the authorized device sources.
    pub coverage: Vec<ActivityCoverage>,
    /// Earliest retained recording time, absent when no retained fact is known.
    pub retained_from: Option<i64>,
}
/// Authorized activity detail. Personal mode never authorizes secrets or raw output.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagementActivityDetail {
    /// Original immutable activity fact.
    pub activity: ManagementActivity,
    /// Whether the current enterprise and OS identity have proven personal ownership.
    pub personal: bool,
    /// Related facts, independently restricted to the same read scope.
    pub related: Vec<ManagementActivity>,
    /// Continuation for related activity history, when needed.
    pub related_cursor: Option<String>,
    /// Explicit absent producer facts or associations.
    pub missing: Vec<String>,
    /// Server observation time for this read.
    pub as_of: i64,
}
