use super::test_support::Participant;
use super::*;
use anyhow::{Result, ensure};
use uuid::Uuid;
#[tokio::test]
#[ignore = "Apple T2: controlled HTTP/2 APNs with certificate authentication"]
async fn production_transport_receipts_are_not_command_evidence() -> Result<()> {
    let participant =
        Participant::start(vec![200, 410, 429, 503, 400], vec![1, 2, 254, 255]).await?;
    let id = Uuid::new_v4();
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    for (status, outcome) in [
        (200, Outcome::Accepted),
        (410, Outcome::Unregistered),
        (429, Outcome::Retryable),
        (503, Outcome::Retryable),
        (400, Outcome::Rejected),
    ] {
        let receipt = participant
            .push
            .send(id, &[1, 2, 254, 255], "fixture-magic", now)
            .await?;
        ensure!(receipt.id == id && receipt.status == status && receipt.outcome == outcome);
    }
    participant.close().await?;
    let oversized = Participant::responses(vec![(200, vec![b' '; 4097])], vec![1], false).await?;
    let receipt = oversized.push.send(id, &[1], "fixture-magic", now).await?;
    ensure!(
        receipt.outcome == Outcome::Retryable && receipt.reason == Some(Reason::InvalidResponse),
        "oversized HTTP 200 response was accepted"
    );
    oversized.close().await
}

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
