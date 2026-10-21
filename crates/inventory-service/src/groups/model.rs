use super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GroupChange {
    /// Product initialization only; the HTTP input never admits this variant.
    #[serde(skip_deserializing)]
    CreateSystem {
        presentation: serde_json::Map<String, serde_json::Value>,
        selector: rss_mdm_group_postgres::SystemSelector,
    },
    Create {
        presentation: serde_json::Map<String, serde_json::Value>,
        criteria: Option<criteria::Condition>,
        asset_context: rss_mdm_group_postgres::AssetContext,
    },
    Edit {
        presentation: serde_json::Map<String, serde_json::Value>,
    },
    Rule {
        criteria: criteria::Condition,
    },
    Members {
        add: Vec<crate::objects::ObjectRef>,
        remove: Vec<crate::objects::ObjectRef>,
    },
    Delete,
    Recompute {},
}
/// Admission parameters for one group calculation, before its input is frozen.
pub struct GroupStart {
    pub id: Uuid,
    pub task: Uuid,
    pub expected: u64,
    pub patch: Option<rss_mdm_group_postgres::MemberPatch>,
    pub publish: bool,
    pub automatic: bool,
    pub at: Timepoint,
}
