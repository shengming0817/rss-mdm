//! Resource's public directory model; query mechanics belong to rss-mdm-query.
use crate::{Id, Kind};
use rss_mdm_query::directory::Schema;
use serde_json::{Map, Value};
/// Default management directory page size.
pub const DEFAULT_LIMIT: u16 = 64;
/// Maximum management directory page size.
pub const MAX_LIMIT: u16 = 1000;
/// Field capabilities derived from the actual checked header model.
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Record>("resource", &["id"], DEFAULT_LIMIT, MAX_LIMIT, &[])
        .and_then(|s| s.validate_with("id", valid_id))
        .and_then(|s| s.validate_with("activeVersion", valid_id))
        .and_then(|s| s.no_range("activeVersion"))
        .expect("Resource model has complete directory semantics")
});
fn valid_id(value: &Value) -> bool {
    value.as_str().is_some_and(|s| Id::new(s).is_ok())
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
/// A checked Resource header, independent of execution materials.
pub struct Record {
    /// Canonical identity checked against the database row.
    pub id: Id,
    /// Database revision checked to be nonnegative.
    #[schemars(range(min = 0))]
    pub revision: i64,
    /// Declaration kind.
    pub kind: Kind,
    /// Whether the aggregate currently has an active version.
    pub active: bool,
    /// At most one current active version.
    pub active_version: Option<Id>,
    /// Validated bounded presentation object.
    #[schemars(with = "crate::Presentation")]
    pub presentation: Map<String, Value>,
}
/// Nested version metadata has its own query identity; the aggregate remains its sole owner.
pub static VERSION_SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(||
    Schema::derived::<VersionRow>("software_versions", &["version"], 64, 1000, &[]).expect("Resource version directory model")
);
/// Public version metadata; shared by the Resource store and software HTTP consumer.
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct VersionRow {
    pub resource: Id,
    pub version: Id,
    pub state: crate::State,
}
