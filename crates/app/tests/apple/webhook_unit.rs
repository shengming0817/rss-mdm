use super::*;
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
