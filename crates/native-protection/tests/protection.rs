use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::TenantId;
fn context(tenant: &str, owner: &str, field: &str) -> DerivedAad {
    ProtectionContext::new(TenantId::parse(tenant).unwrap(), owner, field, 1)
        .unwrap()
        .derive()
}
const TENANT: &str = "11111111-2222-4333-8444-555555555555";
#[test]
fn restart_replay_and_all_native_coordinates_are_authenticated() {
    let key = [27; 32];
    let first = Protector::new(&key).unwrap();
    let restarted = Protector::new(&key).unwrap();
    let aad = context(
        TENANT,
        "registration:3/operation:8/attempt:2",
        "apple.response",
    );
    let plain = b"credential-canary-PIN-1234";
    let sealed = first.seal_bytes(plain, &aad).unwrap();
    assert_ne!(sealed, first.seal_bytes(plain, &aad).unwrap());
    assert!(!sealed.windows(plain.len()).any(|v| v == plain));
    assert_eq!(restarted.open_bytes(&sealed, &aad).unwrap().expose(), plain);
    assert_eq!(first.id(), restarted.id());
    assert_eq!(
        first.mac(plain, &aad).unwrap(),
        restarted.mac(plain, &aad).unwrap()
    );
    assert_ne!(
        first.mac(plain, &aad).unwrap(),
        first.mac(b"credential-canary-PIN-4321", &aad).unwrap()
    );
    for changed in [
        context(
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "registration:3/operation:8/attempt:2",
            "apple.response",
        ),
        context(
            TENANT,
            "registration:4/operation:8/attempt:2",
            "apple.response",
        ),
        context(
            TENANT,
            "registration:3/operation:8/attempt:3",
            "apple.response",
        ),
        context(
            TENANT,
            "registration:3/operation:8/attempt:2",
            "apple.request",
        ),
    ] {
        assert!(restarted.open_bytes(&sealed, &changed).is_err());
        assert_ne!(
            first.mac(plain, &aad).unwrap(),
            first.mac(plain, &changed).unwrap()
        );
    }
    let wrong = Protector::new(&[28; 32]).unwrap();
    assert!(wrong.open_bytes(&sealed, &aad).is_err());
    assert_ne!(
        wrong.mac(plain, &aad).unwrap(),
        first.mac(plain, &aad).unwrap()
    );
    for position in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[position] ^= 1;
        assert!(
            first.open_bytes(&tampered, &aad).is_err(),
            "tampered byte {position}"
        );
    }
    for length in 0..sealed.len() {
        assert!(first.open_bytes(&sealed[..length], &aad).is_err());
    }
    assert!(first.open_bytes(plain, &aad).is_err());
    assert!(!format!("{:?}", first.open_bytes(&sealed, &aad).unwrap()).contains("1234"));
}
#[test]
fn key_length_and_native_storage_budget_are_checked() {
    assert!(Protector::new(&[1; 31]).is_err());
    assert!(Protector::new(&[1; 33]).is_err());
    let protector = Protector::new(&[1; 32]).unwrap();
    let aad = context(TENANT, "operation:1", "input");
    let oversized = vec![0; 32 * 1024 * 1024 + 1];
    assert!(protector.seal_bytes(&oversized, &aad).is_err());
    assert!(protector.mac(&oversized, &aad).is_err());
    let empty = protector.seal_bytes(&[], &aad).unwrap();
    assert!(
        protector
            .open_bytes(&empty, &aad)
            .unwrap()
            .expose()
            .is_empty()
    );
}

#[test]
fn rotation_reads_old_data_and_resumes_rewrap_without_changing_identity() {
    let old = Protector::new(&[11; 32]).unwrap();
    let aad = context(TENANT, "operation:stable", "stored-material");
    let original = old.seal_bytes(b"preserved secret", &aad).unwrap();
    let fingerprint = old.mac(b"original request", &aad).unwrap();
    let rotated = Protector::with_history(&[12; 32], &[&[11; 32]]).unwrap();
    assert_eq!(
        rotated.open_bytes(&original, &aad).unwrap().expose(),
        b"preserved secret"
    );
    assert!(
        rotated
            .verify_mac_with_key(old.id(), b"original request", &aad, &fingerprint)
            .is_ok()
    );
    assert!(
        rotated
            .verify_mac(b"original request", &aad, &fingerprint)
            .is_err()
    );
    assert!(
        rotated
            .verify_mac_with_key(old.id(), b"changed request", &aad, &fingerprint)
            .is_err()
    );
    let rewritten = rotated.rewrap_bytes(&original, &aad).unwrap();
    assert_ne!(original, rewritten);
    assert_eq!(rotated.rewrap_bytes(&rewritten, &aad).unwrap(), rewritten);
    let retired = Protector::new(&[12; 32]).unwrap();
    assert!(retired.open_bytes(&original, &aad).is_err());
    assert_eq!(
        retired.open_bytes(&rewritten, &aad).unwrap().expose(),
        b"preserved secret"
    );
    assert!(old.open_bytes(&rewritten, &aad).is_err());
    let foreign = context(
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "operation:stable",
        "stored-material",
    );
    assert!(rotated.rewrap_bytes(&original, &foreign).is_err());
}
#[test]
fn ring_rejects_duplicates_unknown_keys_and_unbounded_history() {
    assert!(Protector::with_history(&[1; 32], &[&[1; 32]]).is_err());
    assert!(Protector::with_history(&[1; 32], &[&[2; 32], &[2; 32]]).is_err());
    let keys = (2..18).map(|value| [value; 32]).collect::<Vec<_>>();
    let refs = keys.iter().map(|key| key.as_slice()).collect::<Vec<_>>();
    assert!(Protector::with_history(&[1; 32], &refs[..15]).is_ok());
    assert!(Protector::with_history(&[1; 32], &refs).is_err());
    let ring = Protector::with_history(&[1; 32], &[&[2; 32]]).unwrap();
    let aad = context(TENANT, "operation:1", "input");
    let foreign = Protector::new(&[3; 32])
        .unwrap()
        .seal_bytes(b"secret", &aad)
        .unwrap();
    assert!(ring.open_bytes(&foreign, &aad).is_err());
    assert!(
        ring.verify_mac_with_key("unknown", b"secret", &aad, &[0; 32])
            .is_err()
    );
}

#[test]
fn encryption_rotation_preserves_comparison_identity_without_implicit_decrypt_keys() {
    let old = Protector::new(&[21; 32]).unwrap();
    let aad = context(TENANT, "stable-operation", "input");
    let sealed = old.seal_bytes(b"kept material", &aad).unwrap();
    let rotated = Protector::with_fingerprint(&[22; 32], &[&[21; 32]], &[21; 32]).unwrap();
    assert_ne!(old.id(), rotated.id());
    assert_eq!(old.fingerprint_id(), rotated.fingerprint_id());
    assert_eq!(
        old.mac(b"same request", &aad).unwrap(),
        rotated.mac(b"same request", &aad).unwrap()
    );
    let rewritten = rotated.rewrap_bytes(&sealed, &aad).unwrap();
    let retired = Protector::with_fingerprint(&[22; 32], &[], &[21; 32]).unwrap();
    assert!(retired.open_bytes(&sealed, &aad).is_err());
    assert_eq!(
        retired.open_bytes(&rewritten, &aad).unwrap().expose(),
        b"kept material"
    );
    assert!(
        retired
            .verify_mac_with_key(
                old.fingerprint_id(),
                b"same request",
                &aad,
                &old.mac(b"same request", &aad).unwrap()
            )
            .is_ok()
    );
}
