//! Exact source order and budgets for asset continuations. Field projection is frozen at creation.
use rss_mdm_query::window::Schema;
pub static RESULTS: Schema = Schema {
    id: "asset_results",
    default_limit: 1000,
    max_limit: 1000,
    order: "frozen sort key, device",
    context: &[],
};
pub static FACETS: Schema = Schema {
    id: "asset_facets",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "frozen facet label",
    context: &[],
};
pub static SCOPES: Schema = Schema {
    id: "inventory_scopes",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "scope identity at asset cut",
    context: &[],
};
pub static LISTS: Schema = Schema {
    id: "inventory_list_items",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "source array ordinal at asset cut",
    context: &["scope"],
};
pub static COLLECTION_ITEMS: Schema = Schema {
    id: "collection_items",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "sealed collection field ordinal",
    context: &["scope"],
};
pub static FIELD_REFERENCES: Schema = Schema {
    id: "field_references",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "resource, version",
    context: &[],
};
