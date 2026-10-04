use rss_mdm_agent_wire::runtime::*;
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "TaskAuthorization":schemars::schema_for!(TaskAuthorization),
            "TaskResource":schemars::schema_for!(TaskResource),
            "SelfServiceInvoke":schemars::schema_for!(SelfServiceInvoke),
            "SelfServiceDirectory":schemars::schema_for!(SelfServiceDirectory),
            "SelfServiceDirectoryResponse":schemars::schema_for!(SelfServiceDirectoryResponse),
            "SelfServiceAccepted":schemars::schema_for!(SelfServiceAccepted),
            "SelfServiceStatus":schemars::schema_for!(SelfServiceStatus)
        }))
        .unwrap()
    );
}
