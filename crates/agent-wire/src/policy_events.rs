//! Explicit Policy event requests and stable batch acceptance facts.
use super::{PolicyEventName, SoftwareExecutionContext};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
/// Origin supplied by the authenticated service; Policy origins must reference a real parent run.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PolicyEventSource {
    /// Human invocation through the device service or management session.
    Human,
    /// AI invocation through the authenticated service.
    Ai,
    /// A running Policy, validated against the current device.
    Policy {
        /// Parent execution identity.
        run_id: Uuid,
    },
}
/// Explicit event for one authenticated device, never a tenant or device selector.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyEventRequest {
    /// Stable request identity reused after response loss.
    pub operation_id: Uuid,
    /// Canonical Policy trigger name.
    pub event: PolicyEventName,
    /// Real invocation origin, not authorization.
    pub source: PolicyEventSource,
    /// Local context attested by the authenticated Agent; absent for remote management.
    pub execution_context: Option<SoftwareExecutionContext>,
}
/// Stable batch receipt; acceptance does not mean its members executed successfully.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyEventAccepted {
    /// Original request identity.
    pub operation_id: Uuid,
    /// Durable batch identity.
    pub batch_id: Uuid,
    /// Number of frozen members, including rejections.
    pub members: u32,
}
/// An operation remains owned by its original execution subsystem.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyEventOperation {
    /// Existing Agent or software action Run.
    Run {
        /// Run identity.
        id: Uuid,
    },
    /// Existing native command operation.
    Native {
        /// Operation identity.
        id: Uuid,
    },
    /// Existing logical-device retirement.
    Retirement {
        /// Retirement identity.
        id: Uuid,
    },
}
/// Durable member admission facts; running and completion states are read from the operation owner.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyEventDecision {
    /// Processing has not settled yet.
    Pending,
    /// Actual operations were accepted or already exist.
    Accepted {
        /// Exact owner references.
        operations: Vec<PolicyEventOperation>,
    },
    /// Current desired state needs no new operation.
    NoChange {
        /// Stable owner reason.
        reason: String,
    },
    /// A business qualification failed; no child was accepted.
    Rejected {
        /// Stable non-sensitive rejection category.
        reason: String,
    },
    /// The acceptance deadline passed before this member was processed.
    Expired,
}
