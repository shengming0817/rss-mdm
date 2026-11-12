//! Exact source order and budgets for asset continuations. Field projection is frozen at creation.
use rss_mdm_query::window::Schema;
/// Covers a 64 KiB snapshot plus the largest executable collection scope and JSON/Base64 overhead.
pub const MAX_CURSOR_BYTES: usize = 256 * 1024;
/// JSON contains the cursor and a typed executable collection scope, never a URI-sized snapshot.
pub const MAX_PAGE_BODY_BYTES: usize = 384 * 1024;
pub static RESULTS: Schema = Schema {
    id: "asset_results",
    default_limit: 1000,
    max_limit: 1000,
    order: "frozen sort key, device",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Rows belong to one authorized asset query and its frozen sort/cut",
    context: &[],
};
pub static FACETS: Schema = Schema {
    id: "asset_facets",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "frozen facet label",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Facets are derived from the same fixed asset query result",
    context: &[],
};
pub static SCOPES: Schema = Schema {
    id: "inventory_scopes",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "scope identity at asset cut",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Scope identities are read at the continuation-bound AssetCut",
    context: &[],
};
pub static LISTS: Schema = Schema {
    id: "inventory_list_items",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "source array ordinal at asset cut",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "List items retain original source order at the continuation-bound AssetCut",
    context: &["scope"],
};
pub static COLLECTION_ITEMS: Schema = Schema {
    id: "collection_items",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "sealed collection field ordinal",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Items belong to one sealed collection field and preserve its source ordinal",
    context: &["scope"],
};
