//! Immutable result pagination. Each request passes the normal authorization gate.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub cursor: Option<String>,
}
fn default_limit() -> usize {
    1000
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    tenant: String,
    result: Uuid,
    binding: ResultBinding,
    after: String,
}
fn encode(key: &ring::hmac::Key, cursor: Cursor) -> Result<String> {
    let mut bytes = checked_input(serde_json::to_vec(&cursor))?;
    let signature = ring::hmac::sign(key, &bytes);
    bytes.extend_from_slice(signature.as_ref());
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn decode(
    key: &ring::hmac::Key,
    token: &str,
    tenant: &str,
    result: Uuid,
    binding: &ResultBinding,
) -> Result<String> {
    if token.len() > 4096 {
        return Err(Error::Malformed.into());
    }
    let bytes = checked_input(URL_SAFE_NO_PAD.decode(token))?;
    if bytes.len() <= 32 {
        return Err(Error::Malformed.into());
    }
    let (payload, signature) = bytes.split_at(bytes.len() - 32);
    ring::hmac::verify(key, payload, signature).map_err(|_| Error::Conflict)?;
    let cursor: Cursor = serde_json::from_slice(payload).map_err(|_| Error::Conflict)?;
    if cursor.tenant != tenant || cursor.result != result || &cursor.binding != binding {
        return Err(Error::Conflict.into());
    }
    Ok(cursor.after)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
enum ResultBinding {
    Scope { scope: Uuid, kind: ScopePageKind },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopePageKind {
    Members,
    Decisions,
}
mod scope;
#[cfg(test)]
#[path = "../../tests/planning/pages_unit.rs"]
mod tests;
pub use scope::ScopePage;

pub use rss_mdm_inventory_service::groups::pages::{GroupPage, GroupPageKind};
