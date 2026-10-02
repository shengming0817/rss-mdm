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
