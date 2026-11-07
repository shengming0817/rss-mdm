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
    let directories = document["endpoints"]
        .as_array()
        .expect("endpoints")
        .iter()
        .filter_map(|endpoint| {
            let owner = &endpoint["request"]["query_owner"];
            (owner["kind"] == "directory").then(|| (&owner["schema"]["id"], &owner["schema"]))
        })
        .map(|(id, schema)| (id.as_str().expect("directory id"), schema))
        .collect::<std::collections::BTreeMap<_, _>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "resources":resources.into_values().collect::<Vec<_>>(),
            "directoryQueries":directories.into_values().collect::<Vec<_>>()
        }))
        .expect("capabilities serialize")
    );
}
