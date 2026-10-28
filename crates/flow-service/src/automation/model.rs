use crate::assets;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobInput {
    PolicyEvent {
        batch: Uuid,
    },
    PolicyReconcile {
        policy: Uuid,
    },
    Compliance {
        input: Box<crate::compliance::Input>,
    },
    AssetQuery {
        query: Box<assets::Query>,
        scope: assets::ReadScope,
        watermark: i64,
        as_of: i64,
    },
    Scope {
        scope: Uuid,
    },
}
impl JobInput {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Compliance { .. } => "compliance",
            Self::AssetQuery { .. } => "asset_query",
            Self::Scope { .. } => "scope",
            Self::PolicyReconcile { .. } => "policy_reconcile",
            Self::PolicyEvent { .. } => "policy_event",
        }
    }
    pub fn target(&self) -> String {
        match self {
            Self::Compliance { input } => input.rule.to_string(),
            Self::AssetQuery { scope, .. } => scope.subject.clone(),
            Self::Scope { scope } => scope.to_string(),
            Self::PolicyReconcile { policy } => policy.to_string(),
            Self::PolicyEvent { batch } => batch.to_string(),
        }
    }
}
