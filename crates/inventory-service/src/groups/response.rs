//! Group result decoding owned by Inventory, independent of Planning request routing.
use super::*;
use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
view!(Group { id: Uuid, kind: rss_mdm_group_postgres::GroupKind, name: String, description: String, revision: i64, calculation_revision: i64, member_version: i64, member_count: usize, rule_version: Option<String>, deleted: bool });
view!(GroupRead { group: Group, criteria: Option<Criteria>, member_set: Option<Uuid> });
view!(GroupReceipt {
    operation: Uuid,
    group: Group,
    added: usize,
    removed: usize,
    task: Option<Uuid>
});
use crate::tasks::{JobAccepted, TaskRead};
#[derive(Deserialize, Serialize)]
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
