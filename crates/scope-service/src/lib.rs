//! Scope application contracts. F03 (#3042) supplies the application and worker.
//! Participants borrow the initiating transaction; no service owns a second commit.
use rss_mdm_scope::ScopeDefinition;
use serde::{Deserialize, Serialize};

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
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

pub mod sources;
