fn main() {
    use rss_mdm_execution_service::self_service::*;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "DirectoryResponse":schemars::schema_for!(DirectoryResponse),
            "Accepted":schemars::schema_for!(Accepted),
            "Status":schemars::schema_for!(Status)
        }))
        .unwrap()
    );
}
