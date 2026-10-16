use super::test_support::Participant;
use super::*;
use anyhow::{Result, ensure};
use rss_mdm_execution_service::channels::PushOutcome;
use uuid::Uuid;
#[tokio::test]
#[ignore = "Apple T2: controlled HTTP/2 APNs with certificate authentication"]
async fn apns_transport_returns_bounded_correlated_receipts() -> Result<()> {
    let participant = Participant::start(vec![200], vec![1, 2, 254, 255]).await?;
    let id = Uuid::new_v4();
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let receipt = participant
        .push
        .send(id, &[1, 2, 254, 255], "fixture-magic", now)
        .await?;
    ensure!(receipt.id == id && receipt.status == 200 && receipt.outcome == PushOutcome::Accepted);
    participant.close().await?;
    let oversized = Participant::responses(vec![(200, vec![b' '; 4097])], vec![1], false).await?;
    let receipt = oversized.push.send(id, &[1], "fixture-magic", now).await?;
    ensure!(
        receipt.outcome == PushOutcome::Retryable
            && receipt.reason == Some(Reason::InvalidResponse),
        "oversized HTTP 200 response was accepted"
    );
    oversized.close().await
}
