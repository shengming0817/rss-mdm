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
    /// Borrow earlier absolute stage cutoffs; neither cutoff can extend this budget.
    pub fn control_until(
        &self,
        total: Deadline,
        operation: Deadline,
    ) -> rss_audit_postgres::Control<'_, RuntimeTimer> {
        rss_audit_postgres::Control::new(
            &self.timer,
            total.shortened_to(self.deadline.instant()),
            operation.shortened_to(self.operation.instant()),
            &self.cancel,
        )
    }
    /// Borrow the same cutoffs for source work owned and settled by RSS.
    pub fn source_control(&self) -> SourceControl<'_, RuntimeTimer> {
        SourceControl::new(&self.timer, self.deadline, self.operation, &self.cancel)
    }
    pub fn source_control_until(
        &self,
        total: Deadline,
        operation: Deadline,
    ) -> SourceControl<'_, RuntimeTimer> {
        SourceControl::new(
            &self.timer,
            total.shortened_to(self.deadline.instant()),
            operation.shortened_to(self.operation.instant()),
            &self.cancel,
        )
    }
    /// Reborrowing does not start a new timeout or change the cancellation source.
    pub fn control(&self) -> rss_audit_postgres::Control<'_, RuntimeTimer> {
        rss_audit_postgres::Control::new(&self.timer, self.deadline, self.operation, &self.cancel)
    }
}
/// Host budget only. It can stop source work, but cannot commit or acknowledge rollback.
pub struct SourceControl<'a, T> {
    timer: &'a T,
    total: Deadline,
    operation: Deadline,
    cancel: &'a CancellationToken,
}
impl<'a, T: rss_request_context::ExecutionTimer> SourceControl<'a, T> {
    pub fn new(
        timer: &'a T,
        total: Deadline,
        operation: Deadline,
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            timer,
            total,
            operation: operation.shortened_to(total.instant()),
            cancel,
        }
    }
    pub(crate) fn check(&self) -> Result<(), crate::Error> {
        use rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation;
        if self.cancel.is_cancelled() {
            Err(rss_audit_postgres::Error::Cancelled(Operation).into())
        } else if self.operation.is_expired(self.timer.now()) {
            Err(rss_audit_postgres::Error::Deadline(Operation).into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn deadline(&self) -> rss_transactional_messaging::policy::OperationDeadline {
        rss_transactional_messaging::policy::OperationDeadline::from_cutoff(self.total, self.timer)
    }
    pub(crate) async fn run<R, E: From<crate::Error>>(
        &self,
        work: impl Future<Output = Result<R, E>>,
    ) -> Result<R, E> {
        use rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation;
        self.check().map_err(E::from)?;
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(E::from(crate::Error::Audit(rss_audit_postgres::Error::Cancelled(Operation)))),
            () = self.timer.sleep_until(self.operation) => Err(E::from(crate::Error::Audit(rss_audit_postgres::Error::Deadline(Operation)))),
            value = work => value,
        }
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
