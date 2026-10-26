//! Product activity coordinates carried by the original atomic business fact.
//! These values describe facts; they never grant read or execution authority.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use rss_mdm_agent_wire::activities::{
    ActivityDecision, ActivityDelivery, ActivityEffect, ActivityExecution, ActivityKind,
    ActivityOrigin, ActivityPhase, ActivityReporting,
};

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
    /// Exact retirement identity shared by its cleanup and unenrollment work.
    pub retirement: Option<Uuid>,
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
    pub origin: ActivityOrigin,
    pub delivery: Option<ActivityDelivery>,
    pub execution: Option<ActivityExecution>,
    pub effect: Option<ActivityEffect>,
    pub reporting: Option<ActivityReporting>,
    pub decision: Option<ActivityDecision>,
}
impl Activity {
    pub fn new(kind: ActivityKind, phase: ActivityPhase) -> Self {
        Self {
            kind,
            phase,
            target: None,
            links: ActivityLinks::default(),
            user: None,
            origin: ActivityOrigin::System,
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
