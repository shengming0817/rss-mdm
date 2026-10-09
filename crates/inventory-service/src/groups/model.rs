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
    Create {
        name: String,
        description: String,
        criteria: Option<Criteria>,
        asset_context: rss_mdm_group_postgres::AssetContext,
    },
    Edit {
        name: String,
        description: String,
    },
    Rule {
        criteria: Criteria,
    },
    Members {
        add: Vec<rss_mdm_group_postgres::ObjectRef>,
        remove: Vec<rss_mdm_group_postgres::ObjectRef>,
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
