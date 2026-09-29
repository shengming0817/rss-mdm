use super::*;
#[test]
fn cursors_bind_tenant_owner_result_and_projection() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-only");
    let group = Uuid::new_v4();
    let result = Uuid::new_v4();
    let binding = ResultBinding::Scope {
        scope: group,
        kind: ScopePageKind::Members,
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
        ResultBinding::Scope {
            scope: Uuid::new_v4(),
            kind: ScopePageKind::Members,
        },
        ResultBinding::Scope {
            scope: group,
            kind: ScopePageKind::Decisions,
        },
    ] {
        assert!(decode(&key, &token, "tenant-a", result, &other).is_err());
    }
    assert!(decode(&key, &format!("{token}x"), "tenant-a", result, &binding).is_err());
}

#[test]
fn signed_foreign_family_is_rejected() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-only");
    let owner = Uuid::new_v4();
    let result = Uuid::new_v4();
    let value = serde_json::json!({"tenant":"tenant-a","result":result,"binding":{"family":"group","group":owner,"kind":"members"},"after":"device-1"});
    let mut bytes = serde_json::to_vec(&value).unwrap();
    let tag = ring::hmac::sign(&key, &bytes);
    bytes.extend_from_slice(tag.as_ref());
    let token = URL_SAFE_NO_PAD.encode(bytes);
    assert!(
        decode(
            &key,
            &token,
            "tenant-a",
            result,
            &ResultBinding::Scope {
                scope: owner,
                kind: ScopePageKind::Members
            }
        )
        .is_err()
    );
}
