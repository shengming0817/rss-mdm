fn main() {
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "PolicyWrite":schemars::schema_for!(rss_mdm_flow_service::operation::Operation<rss_mdm_policy::Change>),
        "Policy":schemars::schema_for!(rss_mdm_policy::View)
    })).unwrap());
}
