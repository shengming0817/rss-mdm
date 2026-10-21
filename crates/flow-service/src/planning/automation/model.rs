use super::super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceSet {
    pub reference: Reference,
    pub coordinates: rss_mdm_group_postgres::SourceCoordinates,
    pub snapshot: Option<rss_mdm_inventory_service::objects::ObjectSnapshot>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeInput {
    pub definition: ScopeDefinition,
    pub sources: Vec<SourceSet>,
    pub as_of: i64,
}
