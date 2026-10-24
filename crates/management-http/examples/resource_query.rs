//! Resource query documentation is derived from the field authority consumed by execution.
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "endpoint":"GET /api/v1/resources",
            "fields":rss_mdm_resource::directory::FIELDS,
            "defaultLimit":rss_mdm_resource::directory::DEFAULT_LIMIT,
            "maxLimit":rss_mdm_resource::directory::MAX_LIMIT,
            "rawQueryBytes":rss_mdm_query::MAX_RAW_QUERY_BYTES,
            "filterBytes":rss_mdm_query::MAX_FILTER_BYTES,
            "defaultSort":[{"field":"id","descending":false}],
            "page":{"items":"requested projection","nextCursor":"opaque token or null"},
            "consistency":"live keyset; no cross-page snapshot"
        }))
        .expect("query documentation serializes")
    );
}
