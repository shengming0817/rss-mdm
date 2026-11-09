//! Product HTTP projections; storage/core serialization is not the wire contract.
//! ref: serde_derive 1.0.228 src/internals/case.rs
use super::*;
use rss_mdm_scope::ScopeDefinition;
use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
view!(ScopeRead {
    id: Uuid,
    stage:Option<Uuid>,
    retired:bool,
    task:Option<Uuid>,
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
