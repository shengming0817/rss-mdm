use super::*;
use std::os::unix::fs::PermissionsExt;
#[test]
fn startup_file_failures_keep_safe_categories() {
    let scratch = tempfile::tempdir().unwrap();
    let key = scratch.path().join("sensitive-key");
    for (size, mode) in [(0, 0o600), (31, 0o600), (33, 0o600), (32, 0o644)] {
        std::fs::write(&key, vec![7; size]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = protocol_key(&key).unwrap_err();
        assert!(matches!(
            error,
            Error::Configuration(ConfigIssue::ProtocolKey)
        ));
        assert!(!format!("{error:?} {error}").contains("sensitive-key"));
    }
    std::fs::write(&key, [7; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(&**protocol_key(&key).unwrap(), &[7; 32]);
    std::fs::remove_file(&key).unwrap();
    assert!(matches!(
        protocol_key(&key),
        Err(Error::Configuration(ConfigIssue::ProtocolKey))
    ));
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let path = scratch.path().join("sensitive-trust");
    for bytes in [None, Some(vec![9; 31]), Some(vec![9; 64 * 1024 * 1024 + 1])] {
        if let Some(bytes) = bytes {
            std::fs::write(&path, bytes).unwrap();
        }
        let mut config = value["native_protocols"]["windows"].clone();
        config["trust_file"] = serde_json::json!(path);
        let providers = Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![]).unwrap());
        let result = Windows::load(serde_json::from_value(config).unwrap(), 0, providers);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid trust accepted"),
        };
        assert!(matches!(
            error,
            Error::Configuration(ConfigIssue::EnrollmentCa)
        ));
        assert!(!format!("{error:?} {error}").contains("sensitive-trust"));
    }
}
