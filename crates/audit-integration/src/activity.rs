//! Product activity coordinates carried by the original atomic business fact.
//! These values describe facts; they never grant read or execution authority.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    Policy,
    Assignment,
    Batch,
    Execution,
    Configuration,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityPhase {
    Changed,
    Assigned,
    Withdrawn,
    Accepted,
    Offered,
    Dispatched,
    Received,
    Started,
    Reporting,
    Result,
    Reconciled,
    Cancelled,
    Decided,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityTarget {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}

/// Exact producer references. A definition step is qualified by its run and attempt.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityLinks {
    pub policy: Option<Uuid>,
    pub version: Option<Uuid>,
    pub batch: Option<Uuid>,
    pub member: Option<Uuid>,
    pub request: Option<Uuid>,
    pub operation: Option<Uuid>,
    pub task: Option<Uuid>,
    pub attempt: Option<Uuid>,
    pub steps: Vec<String>,
    pub operations: Vec<ActivityOperation>,
}

/// Internal ownership evidence, never part of the ordinary device projection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityUser {
    pub instance: Uuid,
    pub principal: Uuid,
    pub os_identity: String,
    pub generated_uid: Option<String>,
    pub session: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Activity {
    pub kind: ActivityKind,
    pub phase: ActivityPhase,
    pub target: Option<ActivityTarget>,
    pub links: ActivityLinks,
    pub user: Option<ActivityUser>,
    pub origin: String,
    pub delivery: Option<String>,
    pub execution: Option<String>,
    pub effect: Option<String>,
    pub reporting: Option<String>,
    pub decision: Option<String>,
}
impl Activity {
    pub fn new(kind: ActivityKind, phase: ActivityPhase) -> Self {
        Self {
            kind,
            phase,
            target: None,
            links: ActivityLinks::default(),
            user: None,
            origin: "system".into(),
            delivery: None,
            execution: None,
            effect: None,
            reporting: None,
            decision: None,
        }
    }
}

/// Child references returned by the existing batch admission owner.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActivityOperation {
    Run { id: Uuid },
    Native { id: Uuid },
    Retirement { id: Uuid },
}
