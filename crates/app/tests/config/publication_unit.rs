use super::*;
#[test]
fn public_winget_requires_owned_mounts_and_has_no_credential_placeholder() {
    let rings = |origin: &str| serde_json::json!({"test":{"Winget":{"base":format!("{origin}/software/native/sources/enterprise/test/"),"artifacts_base":format!("{origin}/software/native/sources/enterprise/artifacts/")}},"pilot":{"Winget":{"base":format!("{origin}/software/native/sources/enterprise/pilot/"),"artifacts_base":format!("{origin}/software/native/sources/enterprise/artifacts/")}},"production":{"Winget":{"base":format!("{origin}/software/native/sources/enterprise/production/"),"artifacts_base":format!("{origin}/software/native/sources/enterprise/artifacts/")}}});
    let mut value = serde_json::json!({"database":{"host":"localhost","port":5432,"name":"mdm","user":"mdm_software_driver","password_file":"/tmp/password","ca_file":"/tmp/ca"},"sources":[{"name":"enterprise","credentials":{},"rings":rings("https://mdm.example")}]});
    let config: Config = serde_json::from_value(value.clone()).unwrap();
    config.validate_hosted("https://mdm.example").unwrap();
    assert!(config.validate_hosted("https://another.example").is_err());
    value["sources"][0]["credentials"] = serde_json::json!({"unused-future-auth":"/tmp/token"});
    let config: Config = serde_json::from_value(value).unwrap();
    assert!(config.validate_hosted("https://mdm.example").is_err());
}
