use crate::assets;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaskKind {
    Group,
    Scope,
    Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum JobInput {
    AssetQuery {
        query: assets::Query,
        scope: assets::ReadScope,
        watermark: i64,
        as_of: i64,
    },
    Group {
        group: Uuid,
        base_revision: i64,
        watermark: i64,
        publish: bool,
        automatic: bool,
    },
    Scope {
        scope: Uuid,
    },
    Policy {
        policy: String,
        scope: Uuid,
        resolution: Uuid,
        assignment_revision: Option<i64>,
        expected_revision: u64,
        as_of: i64,
    },
}
impl JobInput {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::AssetQuery { .. } => "asset_query",
            Self::Group { publish: true, .. } => "group",
            Self::Group { publish: false, .. } => "group_preview",
            Self::Scope { .. } => "scope",
            Self::Policy { .. } => "policy",
        }
    }
    pub(crate) fn target(&self) -> String {
        match self {
            Self::AssetQuery { scope, .. } => scope.subject.clone(),
            Self::Group { group, .. } => group.to_string(),
            Self::Scope { scope } => scope.to_string(),
            Self::Policy { policy, .. } => policy.clone(),
        }
    }
}
