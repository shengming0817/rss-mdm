use super::*;
#[test]
fn password_is_canonical_256_bits_and_domain_separated() {
    let password = Password::new(random()).unwrap();
    assert_ne!(
        password.digest("tenant-a", "device").unwrap(),
        password.digest("tenant-b", "device").unwrap()
    );
    assert_ne!(
        password.digest("tenant-a", "device").unwrap(),
        password.digest("tenant-a", "other").unwrap()
    );
    for bad in [
        String::new(),
        "a".repeat(42),
        "a".repeat(44),
        "a".repeat(43),
    ] {
        assert!(Password::new(bad).is_err());
    }
    assert!(
        serde_json::from_str::<Create>(
            r#"{"deviceId":"d","password":"bad","expectedGeneration":0}"#
        )
        .is_err()
    );
}

#[test]
fn enrollment_source_is_explicit_and_protocol_bound() {
    let password = random();
    assert!(
        serde_json::from_value::<Create>(serde_json::json!({
            "deviceId":"device-a","password":password,"source":"mdm.apple"
        }))
        .is_ok()
    );
    for value in [
        serde_json::json!({"deviceId":"device-a","password":random()}),
        serde_json::json!({"deviceId":"device-a","password":random(),"channel":"legacy"}),
        serde_json::json!({"deviceId":"device-a","password":random(),"channel":"mdm"}),
        serde_json::json!({"deviceId":"device-a","password":random(),"source":"manual"}),
    ] {
        assert!(serde_json::from_value::<Create>(value).is_err());
    }
}
