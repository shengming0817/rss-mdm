use super::*;
use std::os::unix::fs::PermissionsExt;
#[test]
fn startup_file_failures_keep_safe_categories() {
    let scratch = tempfile::tempdir().unwrap();
    let key = scratch.path().join("sensitive-key");
    let load = || {
        crate::config::NativeProtection {
            active_file: key.clone(),
            historical_files: vec![],
            fingerprint_file: key.clone(),
        }
        .load()
        .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))
    };
    for (size, mode) in [(0, 0o600), (31, 0o600), (33, 0o600), (32, 0o644)] {
        std::fs::write(&key, vec![7; size]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = match load() {
            Err(error) => error,
            Ok(_) => panic!("invalid protocol material accepted"),
        };
        assert!(matches!(
            error,
            Error::Configuration(ConfigIssue::ProtocolKey)
        ));
        assert!(!format!("{error:?} {error}").contains("sensitive-key"));
    }
    std::fs::write(&key, [7; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        load().unwrap().fingerprint_id(),
        rss_mdm_native_protection::Protector::new(&[7; 32])
            .unwrap()
            .id()
    );
    std::fs::remove_file(&key).unwrap();
    assert!(matches!(
        load(),
        Err(Error::Configuration(ConfigIssue::ProtocolKey))
    ));
}
