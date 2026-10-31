//! Authored Policy preview input and stable collection query contracts.
use serde::Deserialize;
/// A draft evaluated against an optional exact Scope result.
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    /// Complete desired Policy definition; preview does not publish it.
    #[serde(deserialize_with = "crate::definition_input")]
    pub definition: Box<crate::Definition>,
    /// Optional Scope publication identity required by the caller.
    pub scope_result: Option<uuid::Uuid>,
}
/// Stable query identity shared by every action's preview provider.
pub static PREVIEW_SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_previews",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &[],
};
/// Stable query identity for Policy's complete-object assignment pages.
pub static ASSIGNMENTS_SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_assignments",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &[],
};
