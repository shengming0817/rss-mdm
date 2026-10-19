fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&schemars::schema_for!(
            rss_mdm_webhook_service::materials::Contract
        ))
        .unwrap()
    );
}
