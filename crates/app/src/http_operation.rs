use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation<T> {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub input: T,
}
