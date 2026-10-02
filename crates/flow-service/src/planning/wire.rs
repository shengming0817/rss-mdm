//! Product HTTP projections; storage/core serialization is not the wire contract.
//! ref: serde_derive 1.0.228 src/internals/case.rs
use super::*;
use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
view!(ScopeRead {
    id: Uuid,
    revision: u64,
    definition: ScopeDefinition,
    resolution:Option<Uuid>,
    resolution_revision:u64
});
view!(ScopeReceipt {
    id: Uuid,
    revision: u64,
    task:Option<Uuid>
});
use rss_mdm_inventory_service::tasks::{JobAccepted, TaskRead};
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum Response {
    JobAccepted(JobAccepted),
    TaskRead(Box<TaskRead>),
    ScopePage(pages::ScopePage),
    ScopeRead(ScopeRead),
    ScopeReceipt(ScopeReceipt),
}
impl Response {
    pub fn decode(value: Value) -> std::result::Result<Self, Error> {
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::PlanningStorage))
    }
}

#[cfg(test)]
#[path = "../../tests/planning/wire_unit.rs"]
mod tests;
