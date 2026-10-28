use super::*;
use serde::{Deserialize, Serialize};
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
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
        #[schemars(extend("x-rss-extension" = "Bounded descriptive group presentation metadata"))]
        presentation: serde_json::Map<String, serde_json::Value>,
        selector: rss_mdm_group_postgres::SystemSelector,
    },
    Create {
        #[schemars(extend("x-rss-extension" = "Bounded descriptive group presentation metadata"))]
        presentation: serde_json::Map<String, serde_json::Value>,
        criteria: Option<criteria::Condition>,
        asset_context: rss_mdm_group::AssetContext,
    },
    Edit {
        #[schemars(extend("x-rss-extension" = "Bounded descriptive group presentation metadata"))]
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
    pub authority: Vec<RequiredAuthority>,
    pub id: Uuid,
    pub task: Uuid,
    pub expected: u64,
    pub patch: Option<rss_mdm_group_postgres::MemberPatch>,
    pub publish: bool,
    pub automatic: bool,
    pub at: Timepoint,
}

/// Accepted definition edit; the existing automation job owns its durable lifetime.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DefinitionEdit {
    pub authority: Vec<RequiredAuthority>,
    pub group: Uuid,
    pub change: Operation<GroupChange>,

    pub at: i64,
}

/// Required current authority captured from a verified principal, not an actor string.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredAuthority {
    pub(super) permission: rss_mdm_authorization_service::Permission,
    pub(super) evidence: rss_mdm_authorization_service::OperationAuthority,
}
