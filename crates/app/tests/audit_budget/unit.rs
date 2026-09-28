use super::*;
#[tokio::test(start_paused = true)]
async fn retirement_reserves_settlement_without_renewing_either_cutoff() {
    let budget = AuditBudget::retirement(None);
    let work = budget.operation_control().remaining();
    assert!(!work.is_zero() && work < budget.control().remaining());
    tokio::time::advance(work).await;
    assert!(budget.operation_control().remaining().is_zero());
    assert!(!budget.control().remaining().is_zero());
    let caller = Deadline::from_timeout(&RuntimeTimer, Duration::from_secs(2)).unwrap();
    let shorter = AuditBudget::retirement(Some(caller));
    assert!(shorter.control().remaining() <= Duration::from_secs(2));
    assert!(shorter.operation_control().remaining() < shorter.control().remaining());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(shorter.control().remaining().is_zero());
    assert!(shorter.operation_control().remaining().is_zero());
}
#[tokio::test]
async fn reborrowing_never_renews_budget_and_keeps_host_cancellation() {
    let cancel = CancellationToken::new();
    let budget = AuditBudget::with_cancellation(Duration::from_millis(20), cancel.clone());
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(budget.control().remaining().is_zero());
    cancel.cancel();
    assert!(budget.cancel.is_cancelled());
}
