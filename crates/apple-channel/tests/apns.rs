use super::*;
#[test]
fn provider_reasons_choose_recovery_without_logging_arbitrary_text() {
    let id = Uuid::nil();
    for (status, body, outcome, reason) in [
        (
            400,
            r#"{"reason":"BadDeviceToken"}"#,
            Outcome::Unregistered,
            Reason::TokenInvalid,
        ),
        (
            400,
            r#"{"reason":"DeviceTokenNotForTopic"}"#,
            Outcome::Unregistered,
            Reason::TokenInvalid,
        ),
        (
            400,
            r#"{"reason":"IdleTimeout"}"#,
            Outcome::Retryable,
            Reason::IdleTimeout,
        ),
        (
            403,
            r#"{"reason":"BadCertificateEnvironment"}"#,
            Outcome::Rejected,
            Reason::Certificate,
        ),
        (
            400,
            r#"{"reason":"BadTopic"}"#,
            Outcome::Rejected,
            Reason::Topic,
        ),
        (
            413,
            r#"{"reason":"PayloadTooLarge"}"#,
            Outcome::Rejected,
            Reason::Payload,
        ),
        (
            400,
            r#"{"reason":"secret-provider-text"}"#,
            Outcome::Retryable,
            Reason::InvalidResponse,
        ),
        (400, "not json", Outcome::Retryable, Reason::InvalidResponse),
    ] {
        let receipt = classify(id, status, body.as_bytes());
        assert_eq!((receipt.outcome, receipt.reason), (outcome, Some(reason)));
    }
}
#[test]
fn persistent_worker_failure_affects_health_and_recovers() {
    let mut health = Health::default();
    let error = Err(Error::Unavailable(Failure::AppleStorage));
    assert!(health.observe(&error).0);
    assert!(health.observe(&error).0);
    assert!(!health.observe(&error).0);
    assert!(health.observe(&Ok(WakeHealth::Idle)).0);
    assert!(!health.observe(&Ok(WakeHealth::Configuration)).0);
    assert!(!health.observe(&Ok(WakeHealth::Idle)).0);
    assert!(health.observe(&Ok(WakeHealth::Healthy)).0);
}
