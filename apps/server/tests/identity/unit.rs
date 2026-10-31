use super::*;
#[test]
fn private_provider_permission_is_explicit_and_tenant_bound() {
    let mut value = serde_json::json!({
        "group_facts_max_age_seconds":300,"state_key_file":"/private/state",
        "active_credential_key":"one","credential_keys":{},"return_targets":{},
        "assurance_profiles":[]
    });
    assert!(serde_json::from_value::<OidcConfig>(value.clone()).is_err());
    value["private_providers"] = serde_json::json!([]);
    let config: OidcConfig = serde_json::from_value(value.clone()).unwrap();
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    assert!(config.private_access(tenant).unwrap().is_empty());
    value["private_providers"] = serde_json::json!([{
        "tenant_id":tenant.to_string(),"issuer":"https://idp.example.test/realms/mdm",
        "client_id":"mdm","cidrs":["10.20.0.0/24"]
    }]);
    let config: OidcConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(config.private_access(tenant).unwrap().len(), 1);
    let other = TenantId::parse("33333333-3333-4333-8333-333333333333").unwrap();
    assert!(config.private_access(other).is_err());
    value["private_providers"][0]["cidrs"] = serde_json::json!(["127.0.0.0/8"]);
    let config: OidcConfig = serde_json::from_value(value).unwrap();
    assert!(config.transport(tenant).is_err());
}
