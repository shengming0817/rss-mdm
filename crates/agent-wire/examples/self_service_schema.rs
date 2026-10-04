use rss_mdm_agent_wire::runtime::*;
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ScriptAuthorization":schemars::schema_for!(ScriptAuthorization),
            "ScriptResource":schemars::schema_for!(ScriptResource),
            "SelfServiceInvoke":schemars::schema_for!(SelfServiceInvoke),
            "SelfServiceDirectory":schemars::schema_for!(SelfServiceDirectory),
            "SelfServiceDirectoryResponse":schemars::schema_for!(SelfServiceDirectoryResponse),
            "SelfServiceAccepted":schemars::schema_for!(SelfServiceAccepted),
            "SelfServiceStatus":schemars::schema_for!(SelfServiceStatus)
        }))
        .unwrap()
    );
}
