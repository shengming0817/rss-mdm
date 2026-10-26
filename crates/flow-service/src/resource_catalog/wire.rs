use super::*;
use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($(#[$attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub struct $name { $($(#[$attr])* pub $field: $ty),* }
    };
}
view!(ResourceReceipt {
    resource: String,
    request: String,
    storage_revision: u64
});
view!(ResourceRead { #[schemars(extend("x-rss-extension" = "Bounded descriptive Resource presentation metadata"))] presentation: serde_json::Map<String, Value>, origin: Option<BlueprintOrigin>, id: String, revision: u64, kind: String, versions: Vec<ResourceVersion> });
view!(BlueprintOrigin {
    blueprint: String,
    version: String,
    digest: [u8; 32]
});
view!(ResourceVersion { id: String, digest: [u8;32], state: String, variants: Vec<Variant> });

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Response {
    Read(ResourceRead),
    Receipt(ResourceReceipt),
}
impl Response {
    pub fn decode(value: Value) -> std::result::Result<Self, Error> {
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::ResourceStorage))
    }
}
