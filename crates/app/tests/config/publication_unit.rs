use super::*;
#[test]
fn public_winget_requires_owned_mounts_and_has_no_credential_placeholder() {
    let mut value = serde_json::json!({"database":{"host":"localhost","port":5432,"name":"mdm","user":"mdm_software_driver","password_file":"/tmp/password","ca_file":"/tmp/ca"},"sources":[{"name":"enterprise","credentials":{},"target":{"Winget":{"base":"https://mdm.example/api/v1/software/native/sources/enterprise/","artifacts_base":"https://mdm.example/api/v1/software/native/sources/enterprise/artifacts/"}}}]});
    let config: Config = serde_json::from_value(value.clone()).unwrap();
    config.validate_hosted("https://mdm.example").unwrap();
    assert!(config.validate_hosted("https://another.example").is_err());
    value["sources"][0]["credentials"] = serde_json::json!({"unused-future-auth":"/tmp/token"});
    let config: Config = serde_json::from_value(value).unwrap();
    assert!(config.validate_hosted("https://mdm.example").is_err());
}
