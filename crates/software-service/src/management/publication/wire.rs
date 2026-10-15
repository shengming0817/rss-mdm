use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
view!(Publication {
    id: [u8; 32],
    attempt: u64,
    outcome: String
});
view!(CandidateRing { ring: String, state: String, publication: Option<Publication> });
#[derive(Deserialize, Serialize)]
#[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub revision: u64,
    pub content_digest: [u8; 32],
    pub disposition: String,
    pub manifest_digest: [u8; 32],
    pub source_snapshot: [u8; 32],
    pub rings: Vec<CandidateRing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<crate::publication::ExportDocument>,
}
