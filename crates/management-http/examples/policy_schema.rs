//! Generate the management Policy artifacts from their actual HTTP and domain types.
fn main() {
    let schemas = serde_json::json!({
        "PolicyWrite": schemars::schema_for!(rss_mdm_flow_service::operation::Operation<rss_mdm_policy::Change>),
        "Policy": schemars::schema_for!(rss_mdm_policy::View),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&schemas).expect("schemas serialize")
    );
}
