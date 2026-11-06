//! Stable result order is owned alongside the implementation.
use rss_mdm_query::window::Schema;
pub static STANDARDS: Schema = Schema {
    id: "standard_software",
    default_limit: 100,
    max_limit: 1000,
    order: "configuration revision, UUID",
    context: &[],
};
pub static BUCKETS: Schema = Schema {
    id: "software_asset_buckets",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen software identity",
    context: &[],
};
pub static DEVICES: Schema = Schema {
    id: "software_asset_devices",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen object identity",
    context: &[],
};
pub static EVIDENCE: Schema = Schema {
    id: "software_asset_evidence",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen evidence identity",
    context: &[],
};
pub static BREAKDOWNS: Schema = Schema {
    id: "software_asset_breakdowns",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen dimension value",
    context: &[],
};

pub static MAPPINGS: Schema = Schema {
    id: "software_mappings",
    default_limit: 100,
    max_limit: 1000,
    order: "configuration revision, UUID",
    context: &[],
};

pub static COVERAGE: Schema = Schema {
    id: "software_asset_coverage",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen object identity",
    context: &[],
};
