use super::super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceSet {
    pub reference: Reference,
    pub member_set: Option<Uuid>,
    pub member_version: u64,
    pub definition_version: u64,
    pub authority_version: u64,
    pub asset_context: rss_mdm_group_postgres::AssetContext,
    pub snapshot: Option<rss_mdm_inventory_service::objects::ObjectSnapshot>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeInput {
    pub definition: ScopeDefinition,
    pub sources: Vec<SourceSet>,
    pub as_of: i64,
}
