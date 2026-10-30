//! Readable projection of this management ingress and its actual field owners.
fn main() {
    let document = rss_mdm_app::http_contract_document().expect("product HTTP contract");
    let resources = document["endpoints"]
        .as_array()
        .expect("endpoints")
        .iter()
        .filter(|endpoint| endpoint["listener"] == "browser")
        .map(|endpoint| {
            (
                endpoint["resource"]["id"].as_str().expect("resource id"),
                &endpoint["resource"],
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "resources":resources.into_values().collect::<Vec<_>>(),
            "directoryQueries":[
                rss_mdm_inventory_service::groups::directory::schema(),
                &rss_mdm_scope_service::directory::SCHEMA,
                &rss_mdm_policy_service::management::read::SCHEMA,
                rss_mdm_inventory_service::compliance::directory::schema(),
                &rss_mdm_inventory_service::assets::saved_directory::SCHEMA,
                &rss_mdm_software_service::management::directory::SOURCES,
                &rss_mdm_software_service::management::publication::directory::PUBLICATIONS,
                &rss_mdm_software_service::management::publication::directory::TARGETS,
                &rss_mdm_resource::directory::VERSION_SCHEMA,
                &rss_mdm_software_service::agent_packages::directory::SCHEMA,
                &rss_mdm_registration_service::agent::configurations::directory::SCHEMA
            ],
            "userAttributeQueryOwner":"App administration::user_profiles::directory::DIRECTORY; bound at real route registration",
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
