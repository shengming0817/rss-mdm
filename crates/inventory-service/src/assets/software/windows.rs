//! Stable result order is owned alongside the implementation.
use rss_mdm_query::window::Schema;
pub static STANDARDS: Schema = Schema {
    id: "standard_software",
    default_limit: 100,
    max_limit: 1000,
    order: "configuration revision, UUID",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "The continuation freezes the software-standard configuration revision",
    context: &[],
};
pub static BUCKETS: Schema = Schema {
    id: "software_asset_buckets",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen software identity",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Rows belong to one fixed software asset query snapshot",
    context: &[],
};
pub static DEVICES: Schema = Schema {
    id: "software_asset_devices",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen object identity",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Rows belong to one fixed software asset query snapshot",
    context: &[],
};
pub static EVIDENCE: Schema = Schema {
    id: "software_asset_evidence",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen evidence identity",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Rows belong to one fixed software asset query snapshot",
    context: &[],
};
pub static BREAKDOWNS: Schema = Schema {
    id: "software_asset_breakdowns",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen dimension value",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Rows belong to one fixed software asset query snapshot",
    context: &[],
};

pub static MAPPINGS: Schema = Schema {
    id: "software_mappings",
    default_limit: 100,
    max_limit: 1000,
    order: "configuration revision, UUID",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "The continuation freezes the complete software-mapping configuration revision",
    context: &[],
};

pub static COVERAGE: Schema = Schema {
    id: "software_asset_coverage",
    default_limit: 100,
    max_limit: 1000,
    order: "frozen object identity",
    purpose: rss_mdm_query::window::Purpose::Snapshot,
    reason: "Rows belong to one fixed software asset query snapshot",
    context: &[],
};
