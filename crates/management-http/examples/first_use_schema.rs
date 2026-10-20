fn main() {
    use rss_mdm_management_http::first_use::{Progress, Receipt, Update};
    let value = serde_json::json!({
        "Update": schemars::schema_for!(Update),
        "Progress": schemars::schema_for!(Progress),
        "Receipt": schemars::schema_for!(Receipt),
    });
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}
