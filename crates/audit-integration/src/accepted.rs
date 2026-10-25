//! Native HTTP handoff and host drain. RSS retains transaction settlement ownership.
//! ref: tokio-util 0.7 src/task/task_tracker.rs (spawn, close and wait).
use std::sync::Arc;

/// Host budget permits retained through accepted work, including transport cancellation.
/// This extension carries lifetime ownership; it grants no authentication or tenant authority.
#[derive(Clone)]
pub struct IngressLease {
    _permits: Arc<Vec<tokio::sync::OwnedSemaphorePermit>>,
}
impl IngressLease {
    pub fn new(permits: Vec<tokio::sync::OwnedSemaphorePermit>) -> Self {
        Self {
            _permits: Arc::new(permits),
        }
    }
}
/// Fully buffered native requests share the host's explicit shutdown drain.
#[derive(Default)]
pub struct AcceptedRequests {
    closed: std::sync::Mutex<bool>,
    tasks: tokio_util::task::TaskTracker,
}
impl AcceptedRequests {
    pub async fn run<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> Option<T> {
        let task = {
            let closed = self
                .closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *closed {
                return None;
            }
            self.tasks.spawn(work)
        };
        task.await.ok()
    }
    pub async fn drain(&self) {
        {
            let mut closed = self
                .closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *closed = true;
            self.tasks.close();
        }
        self.tasks.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn accepted_work_survives_caller_drop_and_shutdown_waits() {
        let accepted = Arc::new(AcceptedRequests::default());
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, waiting) = tokio::sync::oneshot::channel();
        let (done, completed) = tokio::sync::oneshot::channel();
        let owner = accepted.clone();
        let caller = tokio::spawn(async move {
            owner
                .run(async move {
                    entered.send(()).unwrap();
                    waiting.await.unwrap();
                    done.send(()).unwrap();
                })
                .await
        });
        started.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let owner = accepted.clone();
        let drain = tokio::spawn(async move { owner.drain().await });
        tokio::task::yield_now().await;
        assert!(!drain.is_finished());
        release.send(()).unwrap();
        completed.await.unwrap();
        drain.await.unwrap();
        assert!(accepted.run(async { true }).await.is_none());
    }
}
