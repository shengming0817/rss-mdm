use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Explicit tenant-wide product capabilities. Existing roles do not imply these grants.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    GroupRead,
    GroupWrite,
    GroupRecompute,
    ScopeRead,
    ScopeWrite,
    PolicyRead,
    PolicyWrite,
    PlanPreview,
    PlanSave,
    ResourceRead,
    ResourceWrite,
    ReleaseRead,
    ReleaseWrite,
    ReleaseValidate,
    ReleaseApprove,
    ReleasePublish,
    ReleaseWithdraw,
    ReleaseRecover,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation<T> {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub input: T,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Criteria {
    Eq {
        field: String,
        value: String,
    },
    Ne {
        field: String,
        value: String,
    },
    In {
        field: String,
        values: BTreeSet<String>,
    },
    NotIn {
        field: String,
        values: BTreeSet<String>,
    },
    NotContains {
        field: String,
        value: String,
    },
    Contains {
        field: String,
        value: String,
    },
    And {
        children: Vec<Criteria>,
    },
    Or {
        children: Vec<Criteria>,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupChange {
    Create {
        name: String,
        description: String,
        criteria: Option<Criteria>,
    },
    Edit {
        name: String,
        description: String,
    },
    Rule {
        criteria: Criteria,
    },
    Members {
        add: Vec<String>,
        remove: Vec<String>,
    },
    Delete,
    Recompute {
        snapshot: String,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Reference {
    Device(String),
    Group(Uuid),
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScopeDefinition {
    pub targets: BTreeSet<Reference>,
    pub limitations: Option<BTreeSet<Reference>>,
    pub exclusions: BTreeSet<Reference>,
}
impl ScopeDefinition {
    pub fn references(&self) -> BTreeSet<Reference> {
        self.targets
            .iter()
            .chain(self.limitations.iter().flatten())
            .chain(self.exclusions.iter())
            .cloned()
            .collect()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeChange {
    Put { definition: ScopeDefinition },
    Delete,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyChange {
    Create,
    Activate {
        version: u64,
        resource: String,
        resource_version: String,
    },
    Pause,
    Resume,
    Archive,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewInput {
    pub scope: Uuid,
    pub expected_revision: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavePlan {
    pub preview: Uuid,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Source {
    pub reference: Reference,
    pub revision: u64,
    pub member_version: Option<i64>,
    pub members: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Preview {
    pub id: Uuid,
    pub policy: String,
    pub policy_revision: u64,
    pub scope: Uuid,
    pub scope_revision: u64,
    pub as_of: i64,
    pub sources: Vec<Source>,
    pub devices: Vec<String>,
    pub registrations: std::collections::BTreeMap<String, DeviceIdentity>,
    pub explanation: serde_json::Value,
    pub plan: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Registration {
    pub id: String,
    pub channel: String,
    pub generation: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct DeviceIdentity {
    pub revision: u64,
    pub registrations: Vec<Registration>,
}
