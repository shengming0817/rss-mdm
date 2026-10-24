use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Change {
    Publish {
        resource: String,
        version: String,
        expected_resource_revision: u64,
        resource_digest: [u8; 32],
        target: String,
        target_digest: [u8; 32],
    },
    Recover,
    Retry,
    Withdraw,
}
