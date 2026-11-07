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
    Schema::derived::<Record>("resources", &["id"], DEFAULT_LIMIT, MAX_LIMIT, &[])
        .and_then(|s| s.validate_with("id", valid_id))
        .and_then(|s| s.validate_with("activeVersion", valid_id))
        .and_then(|s| s.no_range("id"))
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
/// Stable public kind spelling, including lexical SQL ordering.
pub fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Software => "software",
        Kind::Script => "script",
        Kind::Configuration => "configuration",
        Kind::NativeCollection => "native_collection",
        Kind::AgentCollection => "agent_collection",
        Kind::TelemetryProfile => "telemetry_profile",
    }
}
/// Nested version metadata has its own query identity; the aggregate remains its sole owner.
pub static VERSION_SCHEMA: std::sync::LazyLock<rss_mdm_query::directory::Schema> =
    std::sync::LazyLock::new(|| rss_mdm_query::directory::Schema {
        id: "software_versions",
        keys: &["version"],
        default_limit: 64,
        max_limit: 1000,
        fields: vec![
            rss_mdm_query::directory::Field::scalar(
                "version",
                rss_mdm_query::directory::Kind::Text,
            ),
            rss_mdm_query::directory::Field::scalar(
                "state",
                rss_mdm_query::directory::Kind::enumeration(&[
                    "frozen",
                    "active",
                    "deprecated",
                    "archived",
                ]),
            ),
            rss_mdm_query::directory::Field::output("resource"),
        ],
    });
