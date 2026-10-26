//! Immutable result pagination. Each request passes the normal authorization gate.
use super::*;
use rss_mdm_query::cursor::{CursorCodec, fingerprint};
use serde::{Deserialize, Serialize};

pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "scope_results",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &["channel"],
};
#[derive(Clone, Debug, Serialize)]
pub struct ResultQuery {
    pub page: rss_mdm_query::window::Query,
    pub channel: rss_mdm_inventory::Channel,
}
impl ResultQuery {
    pub fn parse(raw: &str) -> Result<Self> {
        let (page, context) = checked_input(SCHEMA.parse(raw))?;
        let channel = checked_input(serde_json::from_value(serde_json::Value::String(
            context.get("channel").ok_or(Error::Malformed)?.clone(),
        )))?;
        Ok(Self { page, channel })
    }
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
    let context = checked_input(fingerprint(&(
        SCHEMA.id,
        &cursor.tenant,
        cursor.result,
        &cursor.binding,
    )))?;
    Ok(
        checked_input(CursorCodec::from_key(key.clone()).encode(&context, &cursor.after))?
            .as_str()
            .to_owned(),
    )
}
fn decode(
    key: &ring::hmac::Key,
    token: &str,
    tenant: &str,
    result: Uuid,
    binding: &ResultBinding,
) -> Result<String> {
    let context = checked_input(fingerprint(&(SCHEMA.id, tenant, result, binding)))?;
    let token = checked_input(rss_contract::PageCursor::parse(token))?;
    CursorCodec::from_key(key.clone())
        .decode(&token, &context)
        .map_err(|_| Error::Conflict.into())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
enum ResultBinding {
    Scope {
        scope: Uuid,
        kind: ScopePageKind,
        channel: rss_mdm_inventory::Channel,
        subject: String,
    },
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
