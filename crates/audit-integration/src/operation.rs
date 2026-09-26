//! Product work cutoff, separate from the original Audit owner's total settlement cutoff.
use crate::Error;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// Borrow one timer domain, absolute work deadline and cancellation source.
/// This guards only the borrowed product callback; it cannot begin or settle a transaction.
/// Owner control is derived internally; callers cannot pair an independent control with this budget.
/// ```compile_fail
/// use rss_audit_postgres::Control;
/// use rss_mdm_audit_integration::OperationBudget;
/// use rss_request_context::{Deadline, ExecutionTimer};
/// use tokio_util::sync::CancellationToken;
/// fn mismatched<T: ExecutionTimer>(timer: &T, owner: Control<'_, T>, cutoff: Deadline, token: &CancellationToken) {
///     let _ = OperationBudget::new(timer, owner, cutoff, token);
/// }
/// ```
pub struct OperationBudget<'a, T> {
    timer: &'a T,
    deadline: Deadline,
    total: Deadline,
    cancel: &'a CancellationToken,
}
impl<'a, T: ExecutionTimer> OperationBudget<'a, T> {
    pub fn new(
        timer: &'a T,
        total: Deadline,
        deadline: Deadline,
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            timer,
            deadline: deadline.shortened_to(total.instant()),
            total,
            cancel,
        }
    }
    pub(crate) fn owner(&self) -> rss_audit_postgres::Control<'_, T> {
        rss_audit_postgres::Control::new(self.timer, self.total, self.cancel)
    }
    pub fn remaining(&self) -> Duration {
        self.deadline
            .remaining(self.timer.now())
            .unwrap_or_default()
    }
    fn check(&self, deadline: Deadline) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            Err(rss_audit_postgres::Error::Cancelled(LocalTxDeadlineStage::Operation).into())
        } else if deadline.is_expired(self.timer.now()) {
            Err(rss_audit_postgres::Error::Deadline(LocalTxDeadlineStage::Operation).into())
        } else {
            Ok(())
        }
    }
    pub(crate) async fn run<R, E: From<Error>>(
        &self,
        work: impl Future<Output = Result<R, E>>,
    ) -> Result<R, E> {
        let deadline = self.deadline;
        self.check(deadline).map_err(E::from)?;
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(E::from(rss_audit_postgres::Error::Cancelled(LocalTxDeadlineStage::Operation).into())),
            () = self.timer.sleep_until(deadline) => Err(E::from(rss_audit_postgres::Error::Deadline(LocalTxDeadlineStage::Operation).into())),
            result = work => match result {
                Err(error) => Err(error),
                Ok(value) => { self.check(deadline).map_err(E::from)?; Ok(value) },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt, task::AtomicWaker};
    use rss_request_context::Clock;
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Instant,
    };
    struct Manual {
        now: Mutex<Instant>,
        wake: AtomicWaker,
    }
    impl Clock for Manual {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }
    impl ExecutionTimer for Manual {
        async fn sleep_until(&self, deadline: Deadline) {
            futures::future::poll_fn(|cx| {
                self.wake.register(cx.waker());
                if deadline.is_expired(self.now()) {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await
        }
    }
    impl Manual {
        fn advance(&self, duration: Duration) {
            *self.now.lock().unwrap() += duration;
            self.wake.wake();
        }
    }
    #[test]
    #[allow(clippy::disallowed_methods, reason = "manual clock fixture anchor")]
    fn owner_cancellation_cannot_be_replaced_by_another_token() {
        let timer = Manual {
            now: Mutex::new(Instant::now()),
            wake: AtomicWaker::new(),
        };
        let owner_cancel = CancellationToken::new();
        let deadline = Deadline::from_timeout(&timer, Duration::from_secs(60)).unwrap();
        let operation = OperationBudget::new(&timer, deadline, deadline, &owner_cancel);
        owner_cancel.cancel();
        assert!(matches!(
            operation
                .run(std::future::pending::<Result<(), Error>>())
                .now_or_never(),
            Some(Err(_))
        ));
    }
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "fixture supplies one real anchor; execution advances only the injected manual clock"
    )]
    fn injected_clock_and_cancellation_stop_work_without_tokio_time() {
        let timer = Manual {
            now: Mutex::new(Instant::now()),
            wake: AtomicWaker::new(),
        };
        let cancel = CancellationToken::new();
        let owner = rss_audit_postgres::Control::new(
            &timer,
            Deadline::from_timeout(&timer, Duration::from_secs(60)).unwrap(),
            &cancel,
        );
        let deadline = Deadline::from_timeout(&timer, Duration::from_secs(6)).unwrap();
        let control = OperationBudget::new(
            &timer,
            Deadline::from_timeout(&timer, owner.remaining()).unwrap(),
            deadline,
            &cancel,
        );
        timer.advance(Duration::from_secs(4)); // callback arrives late; no new relative budget
        assert_eq!(control.remaining(), Duration::from_secs(2));
        let wait = control.run(std::future::pending::<Result<(), Error>>());
        futures::pin_mut!(wait);
        assert!(wait.as_mut().now_or_never().is_none());
        timer.advance(Duration::from_secs(2));
        assert!(matches!(
            futures::executor::block_on(wait),
            Err(Error::Audit(rss_audit_postgres::Error::Deadline(
                LocalTxDeadlineStage::Operation
            )))
        ));
        let ran = AtomicBool::new(false);
        let result = futures::executor::block_on(control.run(async {
            ran.store(true, Ordering::Release);
            Ok::<_, Error>(())
        }));
        assert!(result.is_err() && !ran.load(Ordering::Acquire));
        let deadline = Deadline::from_timeout(&timer, Duration::from_secs(1)).unwrap();
        let control = OperationBudget::new(
            &timer,
            Deadline::from_timeout(&timer, owner.remaining()).unwrap(),
            deadline,
            &cancel,
        );
        let wait = control.run(std::future::pending::<Result<(), Error>>());
        futures::pin_mut!(wait);
        assert!(wait.as_mut().now_or_never().is_none());
        cancel.cancel();
        assert!(matches!(
            futures::executor::block_on(wait),
            Err(Error::Audit(rss_audit_postgres::Error::Cancelled(
                LocalTxDeadlineStage::Operation
            )))
        ));
        let result = futures::executor::block_on(control.run(async {
            ran.store(true, Ordering::Release);
            Ok::<_, Error>(())
        }));
        assert!(result.is_err() && !ran.load(Ordering::Acquire));
    }
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "fixture supplies only an anchor for its injected manual clock"
    )]
    fn owner_cutoff_caps_a_later_operation_deadline() {
        let timer = Manual {
            now: Mutex::new(Instant::now()),
            wake: AtomicWaker::new(),
        };
        let cancel = CancellationToken::new();
        let owner = rss_audit_postgres::Control::new(
            &timer,
            Deadline::from_timeout(&timer, Duration::from_secs(2)).unwrap(),
            &cancel,
        );
        let control = OperationBudget::new(
            &timer,
            Deadline::from_timeout(&timer, owner.remaining()).unwrap(),
            Deadline::from_timeout(&timer, Duration::from_secs(10)).unwrap(),
            &cancel,
        );
        let wait = control.run(std::future::pending::<Result<(), Error>>());
        futures::pin_mut!(wait);
        assert!(wait.as_mut().now_or_never().is_none());
        timer.advance(Duration::from_secs(2));
        assert!(matches!(
            futures::executor::block_on(wait),
            Err(Error::Audit(rss_audit_postgres::Error::Deadline(
                LocalTxDeadlineStage::Operation
            )))
        ));
        let ran = AtomicBool::new(false);
        assert!(
            futures::executor::block_on(control.run(async {
                ran.store(true, Ordering::Release);
                Ok::<_, Error>(())
            }))
            .is_err()
        );
        assert!(!ran.load(Ordering::Acquire));
    }
}
