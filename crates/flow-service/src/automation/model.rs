use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobInput {
    PolicyEvent { batch: Uuid },
    PolicyReconcile { policy: Uuid },
    PolicyScope { scope: Uuid, run: Uuid },
}
impl JobInput {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PolicyScope { .. } => "policy_scope",
            Self::PolicyReconcile { .. } => "policy_reconcile",
            Self::PolicyEvent { .. } => "policy_event",
        }
    }
    pub fn target(&self) -> String {
        match self {
            Self::PolicyScope { scope, .. } => scope.to_string(),
            Self::PolicyReconcile { policy } => policy.to_string(),
            Self::PolicyEvent { batch } => batch.to_string(),
        }
    }
}
