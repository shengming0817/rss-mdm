//! Host-owned lifetime for one absolute Audit budget. Transaction ownership stays in Audit/RSS.
//! ref: rss-audit-postgres Control: borrows the timer and cancellation token, copies the cutoff.
use crate::lifecycle::RuntimeTimer;
use rss_request_context::Deadline;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(crate) struct AuditBudget {
    timer: RuntimeTimer,
    deadline: Deadline,
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
            cancel,
        }
    }
    /// Reborrowing does not start a new timeout or change the cancellation source.
    pub(crate) fn control(&self) -> rss_audit_postgres::Control<'_, RuntimeTimer> {
        rss_audit_postgres::Control::new(&self.timer, self.deadline, &self.cancel)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
