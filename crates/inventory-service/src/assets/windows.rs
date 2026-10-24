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
    id: "asset_queries",
    default_limit: 1000,
    max_limit: 1000,
    order: "frozen facet label",
    context: &[],
};
pub static SCOPES: Schema = Schema {
    id: "devices",
    default_limit: 50,
    max_limit: 100,
    order: "scope identity at watermark",
    context: &[],
};
pub static LISTS: Schema = Schema {
    id: "devices",
    default_limit: 50,
    max_limit: 100,
    order: "source array ordinal at watermark",
    context: &["scope"],
};
pub static COLLECTION_ITEMS: Schema = Schema {
    id: "devices",
    default_limit: 100,
    max_limit: 1000,
    order: "sealed collection field ordinal",
    context: &["scope"],
};
pub static FIELD_REFERENCES: Schema = Schema {
    id: "asset_fields",
    default_limit: 64,
    max_limit: 128,
    order: "resource, version",
    context: &[],
};
