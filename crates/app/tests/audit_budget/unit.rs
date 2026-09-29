use super::*;
#[tokio::test(start_paused = true)]
async fn retirement_reserves_settlement_without_renewing_either_cutoff() {
    let budget = AuditBudget::retirement(None);
    let work = budget.control().operation_remaining();
    assert!(!work.is_zero() && work < budget.control().total_remaining());
    tokio::time::advance(work).await;
    assert!(budget.control().operation_remaining().is_zero());
    assert!(!budget.control().total_remaining().is_zero());
    let caller = Deadline::from_timeout(&RuntimeTimer, Duration::from_secs(2)).unwrap();
    let shorter = AuditBudget::retirement(Some(caller));
    assert!(shorter.control().total_remaining() <= Duration::from_secs(2));
    assert!(shorter.control().operation_remaining() < shorter.control().total_remaining());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(shorter.control().total_remaining().is_zero());
    assert!(shorter.control().operation_remaining().is_zero());
}
#[tokio::test]
async fn reborrowing_never_renews_budget_and_keeps_host_cancellation() {
    let cancel = CancellationToken::new();
    let budget = AuditBudget::with_cancellation(Duration::from_millis(20), cancel.clone());
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(budget.control().total_remaining().is_zero());
    cancel.cancel();
    assert!(budget.cancel.is_cancelled());
}
