use super::super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::management) enum TaskKind {
    Group,
    Scope,
    Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::management) enum JobInput {
    Group {
        group: Uuid,
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
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Group { publish: true, .. } => "group",
            Self::Group { publish: false, .. } => "group_preview",
            Self::Scope { .. } => "scope",
            Self::Policy { .. } => "policy",
        }
    }
    pub(super) fn target(&self) -> String {
        match self {
            Self::Group { group, .. } => group.to_string(),
            Self::Scope { scope } => scope.to_string(),
            Self::Policy { policy, .. } => policy.clone(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::management) struct SourceSet {
    pub reference: Reference,
    pub member_set: Option<Uuid>,
    pub member_version: u64,
    pub definition_version: u64,
    pub authority_version: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::management) struct ScopeInput {
    pub definition: ScopeDefinition,
    pub sources: Vec<SourceSet>,
    pub as_of: i64,
}
