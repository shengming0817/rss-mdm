//! Product-owned lifetime for one absolute Audit budget. Transaction ownership stays in Audit/RSS.
//! ref: rss-audit-postgres Control: borrows the timer and cancellation token, copies the cutoff.

use rss_request_context::Deadline;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct AuditBudget {
    timer: RuntimeTimer,
    deadline: Deadline,
    operation: Deadline,
    cancel: CancellationToken,
}
impl AuditBudget {
    /// Call sites supply bounded product constants, never an untrusted duration.
    pub fn new(timeout: Duration) -> Self {
        Self::with_cancellation(timeout, CancellationToken::new())
    }
    pub fn with_cancellation(timeout: Duration, cancel: CancellationToken) -> Self {
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
    pub fn retirement(caller: Option<Deadline>) -> Self {
        Self::retirement_with_total(Duration::from_secs(6), caller)
    }
    #[cfg(any(test, feature = "integration"))]
    pub fn retirement_test(total: Duration, caller: Option<Deadline>) -> Self {
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
    /// Reborrowing does not start a new timeout or change the cancellation source.
    pub fn control(&self) -> rss_audit_postgres::Control<'_, RuntimeTimer> {
        rss_audit_postgres::Control::new(&self.timer, self.deadline, self.operation, &self.cancel)
    }
}
#[cfg(test)]
#[path = "../tests/budget/unit.rs"]
mod tests;

/// The concrete product timer; no transaction or runtime ownership is transferred.
pub struct RuntimeTimer;
impl rss_request_context::Clock for RuntimeTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete product audit clock uses Tokio time"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for RuntimeTimer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
