use super::*;
use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub(super) struct $name { $(pub $field: $ty),* }
    };
}
view!(ResourceReceipt {
    resource: String,
    request: String,
    storage_revision: u64
});
view!(ResourceRead { id: String, revision: u64, kind: String, versions: Vec<ResourceVersion> });
view!(ResourceVersion { configuration: Option<serde_json::Value>, id: String, digest: [u8;32], state: String, variants: Vec<Variant> });

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum Response {
    Read(ResourceRead),
    Receipt(ResourceReceipt),
}
impl Response {
    pub fn decode(value: Value) -> std::result::Result<Self, Error> {
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::ManagementStorage))
    }
}
