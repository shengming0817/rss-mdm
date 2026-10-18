use http::HeaderMap;
use rss_mdm_pki_service::scep::decode;
#[test]
fn signed_body_is_required_and_replay_window_is_bounded() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-secret");
    let bytes=br#"{"timestamp":"2026-09-23T00:00:00Z","x509CertificateRequest":{"raw":"AQ=="},"scepTransactionID":"tx"}"#;
    let signature = ring::hmac::sign(&key, bytes)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let mut headers = HeaderMap::new();
    headers.insert("x-smallstep-webhook-id", "rss".parse().unwrap());
    headers.insert("x-smallstep-signature", signature.parse().unwrap());
    let now = time::OffsetDateTime::parse(
        "2026-09-23T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp();
    assert!(decode(&key, "rss", &headers, bytes, now).is_ok());
    assert!(decode(&key, "rss", &headers, bytes, now + 301).is_err());
    assert!(decode(&key, "other", &headers, bytes, now).is_err());
    assert!(decode(&key, "rss", &headers, b"{}", now).is_err());
    headers.append("x-smallstep-signature", signature.parse().unwrap());
    assert!(decode(&key, "rss", &headers, bytes, now).is_err());
}

#[test]
fn issuer_bound_callbacks_reject_cross_stage_and_ambiguous_ids() {
    use rss_mdm_pki_service::scep::{Credentials, Stage, Verifier};
    let credential = |issuer: char, id: &str| Credentials {
        issuer: issuer.to_string().repeat(64),
        challenge_id: format!("{id}-challenge"),
        challenge_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, id.as_bytes()),
        notify_id: format!("{id}-notify"),
        notify_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"different-notify-key"),
    };
    assert!(Verifier::new(vec![credential('a', "a"), credential('b', "a")]).is_err());
    assert!(Verifier::new(vec![credential('a', "a"), credential('a', "b")]).is_err());
    let verifier = Verifier::new(vec![credential('a', "a"), credential('b', "b")]).unwrap();
    // Both CAs deliberately use the same provisioner name. It is not authentication.
    let bytes=br#"{"timestamp":"2026-09-23T00:00:00Z","provisionerName":"rss","x509CertificateRequest":{"raw":"AQ=="},"scepTransactionID":"tx"}"#;
    let now = time::OffsetDateTime::parse(
        "2026-09-23T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp();
    let mut headers = HeaderMap::new();
    let (id, signature) = verifier
        .signature_fixture(&"a".repeat(64), Stage::Challenge, bytes)
        .unwrap();
    headers.insert("x-smallstep-webhook-id", id.parse().unwrap());
    headers.insert(
        "x-smallstep-signature",
        signature
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>()
            .parse()
            .unwrap(),
    );
    let proof = verifier
        .verify(Stage::Challenge, &headers, bytes, now)
        .unwrap();
    assert_eq!(proof.issuer(), "a".repeat(64));
    assert_eq!(proof.request().provisioner_name.as_deref(), Some("rss"));
    assert!(
        verifier
            .verify(Stage::Notify, &headers, bytes, now)
            .is_err()
    );
    headers.insert("x-smallstep-webhook-id", "b-challenge".parse().unwrap());
    assert!(
        verifier
            .verify(Stage::Challenge, &headers, bytes, now)
            .is_err()
    );
    headers.insert("x-smallstep-webhook-id", "a-challenge".parse().unwrap());
    headers.append("x-smallstep-webhook-id", "a-challenge".parse().unwrap());
    assert!(
        verifier
            .verify(Stage::Challenge, &headers, bytes, now)
            .is_err()
    );
}
