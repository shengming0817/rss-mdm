//! Host-owned lifetime for one absolute Audit budget. Transaction ownership stays in Audit/RSS.
//! ref: rss-audit-postgres Control: borrows the timer and cancellation token, copies the cutoff.
use crate::lifecycle::RuntimeTimer;
use rss_request_context::Deadline;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(crate) struct AuditBudget {
    timer: RuntimeTimer,
    deadline: Deadline,
    operation: Deadline,
    cancel: CancellationToken,
}
impl AuditBudget {
    /// Call sites supply bounded product constants, never an untrusted duration.
    pub(crate) fn new(timeout: Duration) -> Self {
        Self::with_cancellation(timeout, CancellationToken::new())
    }
    pub(crate) fn with_cancellation(timeout: Duration, cancel: CancellationToken) -> Self {
        let timer = RuntimeTimer;
        let deadline = Deadline::from_timeout(&timer, timeout).expect("bounded host audit budget");
        Self {
            timer,
            deadline,
            operation: deadline,
            cancel,
        }
    }
    /// Preserve the existing six-second product cap, reserving a quarter for owner settlement.
    /// Caller cutoffs are absolute; neither a late callback nor reborrowing renews the budget.
    pub(crate) fn retirement(caller: Option<Deadline>) -> Self {
        Self::retirement_with_total(Duration::from_secs(6), caller)
    }
    #[cfg(test)]
    pub(crate) fn retirement_test(total: Duration, caller: Option<Deadline>) -> Self {
        Self::retirement_with_total(total, caller)
    }
    fn retirement_with_total(total: Duration, caller: Option<Deadline>) -> Self {
        use rss_request_context::Clock;
        let mut budget = Self::new(total);
        if let Some(caller) = caller {
            budget.deadline = Deadline::at(budget.deadline.instant().min(caller.instant()));
        }
        let now = budget.timer.now();
        let remaining = budget.deadline.remaining(now).unwrap_or_default();
        budget.operation = Deadline::at(now + remaining.mul_f64(0.75));
        budget
    }
    pub(crate) fn operation_control(
        &self,
    ) -> rss_mdm_audit_integration::OperationBudget<'_, RuntimeTimer> {
        rss_mdm_audit_integration::OperationBudget::new(
            &self.timer,
            self.deadline,
            self.operation,
            &self.cancel,
        )
    }
    /// Reborrowing does not start a new timeout or change the cancellation source.
    pub(crate) fn control(&self) -> rss_audit_postgres::Control<'_, RuntimeTimer> {
        rss_audit_postgres::Control::new(&self.timer, self.deadline, &self.cancel)
    }
}
#[cfg(test)]
mod tests {
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
}
