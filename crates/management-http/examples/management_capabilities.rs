//! Readable projection of the production resource declarations and their actual Resource field owner.
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "resources":rss_mdm_http_contract::catalog::ALL,
            "operationGaps":rss_mdm_http_contract::catalog::GAPS,
            "resourceQueryOwner":{
                "fields":rss_mdm_resource::directory::FIELDS,
                "defaultLimit":rss_mdm_resource::directory::DEFAULT_LIMIT,
                "maxLimit":rss_mdm_resource::directory::MAX_LIMIT,
                "defaultSort":["id"],
                "pagination":"signed cursor / nextCursor",
                "projection":"selectable; absent means all output fields; empty is rejected"
            }
        }))
        .expect("capabilities serialize")
    );
}
