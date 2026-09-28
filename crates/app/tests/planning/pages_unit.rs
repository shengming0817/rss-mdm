use super::*;
#[test]
fn cursors_bind_tenant_owner_result_and_projection() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-only");
    let group = Uuid::new_v4();
    let result = Uuid::new_v4();
    let binding = ResultBinding::Group {
        group,
        kind: GroupPageKind::Members,
    };
    let token = encode(
        &key,
        Cursor {
            tenant: "tenant-a".into(),
            result,
            binding: binding.clone(),
            after: "device-1".into(),
        },
    )
    .unwrap();
    assert_eq!(
        decode(&key, &token, "tenant-a", result, &binding).unwrap(),
        "device-1"
    );
    assert!(decode(&key, &token, "tenant-b", result, &binding).is_err());
    assert!(decode(&key, &token, "tenant-a", Uuid::new_v4(), &binding).is_err());
    for other in [
        ResultBinding::Group {
            group: Uuid::new_v4(),
            kind: GroupPageKind::Members,
        },
        ResultBinding::Group {
            group,
            kind: GroupPageKind::Decisions,
        },
        ResultBinding::Scope {
            scope: group,
            kind: ScopePageKind::Members,
        },
    ] {
        assert!(decode(&key, &token, "tenant-a", result, &other).is_err());
    }
    assert!(decode(&key, &format!("{token}x"), "tenant-a", result, &binding).is_err());
}
