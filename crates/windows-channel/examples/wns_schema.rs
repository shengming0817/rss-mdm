use rss_mdm_windows_channel::wns_materials::*;
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "Import":schemars::schema_for!(Request),
            "Revoke":schemars::schema_for!(RevokeRequest),
            "Operation":schemars::schema_for!(Operation),
            "Directory":schemars::schema_for!(Directory)
        }))
        .unwrap()
    );
}
