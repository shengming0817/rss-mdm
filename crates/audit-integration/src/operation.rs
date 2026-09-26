//! Product work cutoff, separate from the original Audit owner's total settlement cutoff.
use crate::Error;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// Borrow one timer domain, absolute work deadline and cancellation source.
/// This guards only the borrowed product callback; it cannot begin or settle a transaction.
pub struct OperationControl<'a, T> {
    timer: &'a T,
    deadline: Deadline,
    cancel: &'a CancellationToken,
}
impl<'a, T: ExecutionTimer> OperationControl<'a, T> {
    pub const fn new(timer: &'a T, deadline: Deadline, cancel: &'a CancellationToken) -> Self {
        Self {
            timer,
            deadline,
            cancel,
        }
    }
    pub fn remaining(&self) -> Duration {
        self.deadline
            .remaining(self.timer.now())
            .unwrap_or_default()
    }
    fn check(&self) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            Err(rss_audit_postgres::Error::Cancelled(LocalTxDeadlineStage::Operation).into())
        } else if self.deadline.is_expired(self.timer.now()) {
            Err(rss_audit_postgres::Error::Deadline(LocalTxDeadlineStage::Operation).into())
        } else {
            Ok(())
        }
    }
    pub(crate) async fn run<R, E: From<Error>>(
        &self,
        work: impl Future<Output = Result<R, E>>,
    ) -> Result<R, E> {
        self.check().map_err(E::from)?;
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(E::from(rss_audit_postgres::Error::Cancelled(LocalTxDeadlineStage::Operation).into())),
            () = self.timer.sleep_until(self.deadline) => Err(E::from(rss_audit_postgres::Error::Deadline(LocalTxDeadlineStage::Operation).into())),
            result = work => match result {
                Err(error) => Err(error),
                Ok(value) => { self.check().map_err(E::from)?; Ok(value) },
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
        let deadline = Deadline::from_timeout(&timer, Duration::from_secs(6)).unwrap();
        let control = OperationControl::new(&timer, deadline, &cancel);
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
        let control = OperationControl::new(&timer, deadline, &cancel);
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
}
