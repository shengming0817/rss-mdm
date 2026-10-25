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
#[tokio::test(start_paused = true)]
async fn reborrowing_never_renews_budget_and_keeps_host_cancellation() {
    let cancel = CancellationToken::new();
    let budget = AuditBudget::with_cancellation(Duration::from_millis(20), cancel.clone());
    let first = budget.control();
    let source = budget.source_control();
    tokio::time::advance(Duration::from_millis(10)).await;
    assert_eq!(first.total_remaining(), Duration::from_millis(10));
    assert_eq!(budget.control().total_remaining(), first.total_remaining());
    assert_eq!(
        budget.source_control().operation.instant(),
        source.operation.instant()
    );
    cancel.cancel();
    let result = budget
        .source_control()
        .run(async {
            panic!("cancelled source work ran");
            #[allow(unreachable_code)]
            Ok::<(), crate::Error>(())
        })
        .await;
    assert!(matches!(
        result,
        Err(crate::Error::Audit(rss_audit_postgres::Error::Cancelled(_)))
    ));
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(budget.control().total_remaining().is_zero());
}

#[tokio::test(start_paused = true)]
async fn stage_cutoffs_only_shorten_and_leave_time_for_final_read() {
    let budget = AuditBudget::new(Duration::from_secs(5));
    let total = Deadline::from_timeout(&RuntimeTimer, Duration::from_secs(2)).unwrap();
    let operation = Deadline::from_timeout(&RuntimeTimer, Duration::from_millis(1500)).unwrap();
    let stage = budget.control_until(total, operation);
    tokio::time::advance(Duration::from_millis(1500)).await;
    assert!(stage.operation_remaining().is_zero());
    assert_eq!(stage.total_remaining(), Duration::from_millis(500));
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(budget.control().total_remaining(), Duration::from_secs(3));
    let late = Deadline::from_timeout(&RuntimeTimer, Duration::from_secs(30)).unwrap();
    assert_eq!(
        budget.control_until(late, late).total_remaining(),
        Duration::from_secs(3)
    );
}
