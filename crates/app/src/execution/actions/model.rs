use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
