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
