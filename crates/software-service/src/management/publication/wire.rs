use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publication {
    pub id: String,
    pub revision: u64,
    pub target: String,
    pub resource: String,
    pub version: String,
    pub publication: [u8; 32],
    pub content_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub attempt: u64,
    pub outcome: String,
    pub withdrawn: bool,
    pub withdrawal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<crate::publication::ExportDocument>,
}
