use crate::Query;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    pub tenant: String,
    pub instance: String,
    pub authority: String,
    pub family: String,
    pub query: Query,
    pub generation: uuid::Uuid,
    pub through: i64,
    pub after_at: i64,
    pub after_position: i64,
}
