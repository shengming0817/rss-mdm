use crate::*;
use rss_mdm_query::cursor::CursorCodec;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    pub context: Value,
    pub offset: usize,
}
impl Associations {
    pub(crate) fn encode(&self, context: Value, offset: usize) -> Result<String> {
        CursorCodec::from_key(self.key.clone())
            .encode("device-associated-pages", &Cursor { context, offset })
            .map(|v| v.as_str().to_owned())
            .map_err(|_| Error::Malformed)
    }
    pub(crate) fn decode(&self, value: &str) -> Result<Cursor> {
        CursorCodec::from_key(self.key.clone())
            .decode(
                &rss_contract::PageCursor::parse(value).map_err(|_| Error::Malformed)?,
                "device-associated-pages",
            )
            .map_err(|_| Error::CursorInvalidated)
    }
}
