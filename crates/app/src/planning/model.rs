use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub(crate) use super::assets::Criteria;
pub use crate::authorization::Permission;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
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
    Recompute {},
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ScopeChange {
    Put { definition: ScopeDefinition },
    Delete,
}
