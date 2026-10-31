//! Immutable configuration publication, authenticated to its Policy version.
use super::definition::Protected;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frozen {
    Configuration {
        #[serde(rename = "native_sealed")]
        native: Protected,
        platform: rss_mdm_policy::Platform,
        exit: rss_mdm_policy::Exit,
        resource_digest: [u8; 32],
    },
}
