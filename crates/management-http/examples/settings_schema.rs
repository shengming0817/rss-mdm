fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&schemars::schema_for!(
            rss_mdm_management_http::settings::Catalog
        ))
        .unwrap()
    );
}
