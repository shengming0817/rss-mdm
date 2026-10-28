//! Group result decoding owned by Inventory, independent of Planning request routing.
use super::*;
use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($(#[$attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub struct $name { $($(#[$attr])* pub $field: $ty),* }
    };
}
view!(Group { id: Uuid, kind: rss_mdm_group_postgres::GroupKind, system_selector: Option<rss_mdm_group_postgres::SystemSelector>, asset_context: rss_mdm_group::AssetContext, #[schemars(extend("x-rss-extension" = "Bounded descriptive group presentation metadata"))] presentation: serde_json::Map<String, serde_json::Value>, revision: i64, calculation_revision: i64, member_version: i64, member_count: usize, rule_version: Option<String>, deleted: bool });
view!(GroupRead { group: Group, criteria: Option<criteria::Condition>, member_set: Option<Uuid>, freshness: references::Freshness });
view!(GroupReceipt {
    operation: Uuid,
    group: Group,
    added: usize,
    removed: usize,
    task: Option<Uuid>
});
use crate::tasks::{JobAccepted, TaskRead};
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Response {
    JobAccepted(JobAccepted),
    TaskRead(Box<TaskRead>),
    GroupRead(GroupRead),
    GroupPage(pages::GroupPage),
    GroupReceipt(GroupReceipt),
}
impl Response {
    pub fn decode(value: Value) -> std::result::Result<Self, Error> {
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::AssetsStorage))
    }
}
