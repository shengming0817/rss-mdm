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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub after: Option<String>,
    #[serde(default = "page_size")]
    pub limit: usize,
    pub target: Option<String>,
    pub resource: Option<String>,
    pub version: Option<String>,
    pub operation_id: Option<uuid::Uuid>,
}
fn page_size() -> usize {
    20
}
impl Query {
    pub fn validate(&self) -> bool {
        (1..=100).contains(&self.limit)
            && [&self.after, &self.target, &self.resource, &self.version]
                .iter()
                .all(|v| {
                    v.as_ref().is_none_or(|s| {
                        !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
                    })
                })
    }
}
