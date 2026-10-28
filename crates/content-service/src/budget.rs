//! One content-operation deadline, with bounded time reserved for settlement and cleanup.
use crate::{Error, Store};
use rss_request_context::{Clock, Deadline};
use std::{future::Future, time::Duration};

#[derive(Clone, Copy)]
pub struct UploadBudget {
    pub(crate) total: Deadline,
    pub(crate) operation: Deadline,
}
impl UploadBudget {
    pub fn operation_deadline(self) -> Deadline {
        self.operation
    }
    pub(crate) fn new(clock: &dyn Clock, duration: Duration) -> Result<Self, Error> {
        let total = Deadline::from_timeout(clock, duration).map_err(|_| Error::Configuration)?;
        let reserve = Duration::from_secs(6).min(duration / 4);
        Ok(Self {
            total,
            operation: Deadline::at(total.instant() - reserve),
        })
    }
    pub(crate) fn remaining(self) -> Duration {
        self.total
            .remaining(rss_mdm_audit_integration::budget::RuntimeTimer.now())
            .unwrap_or_default()
    }
    pub(crate) async fn work<T, E: From<Error>>(
        self,
        future: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        tokio::time::timeout_at(self.operation.instant().into(), future)
            .await
            .map_err(|_| E::from(Error::Deadline))?
    }
}
impl Store {
    pub fn upload_budget(&self) -> Result<UploadBudget, Error> {
        UploadBudget::new(
            self.timer.as_ref(),
            Duration::from_secs(self.config.transfer_seconds),
        )
    }
}

/// The exact lease is known before claim may commit; cancellation never loses its identity.
pub(crate) struct UploadLease {
    store: Store,
    key: uuid::Uuid,
    epoch: uuid::Uuid,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    released: bool,
    temporary: u64,
    _admission: std::sync::Arc<crate::gate::Permit>,
}
impl UploadLease {
    pub(crate) fn new(
        store: &Store,
        key: uuid::Uuid,
        epoch: uuid::Uuid,
        permit: tokio::sync::OwnedSemaphorePermit,
        admission: std::sync::Arc<crate::gate::Permit>,
    ) -> Self {
        Self {
            store: store.clone(),
            key,
            epoch,
            permit: Some(permit),
            released: false,
            temporary: 0,
            _admission: admission,
        }
    }
    pub(crate) fn admission(&self) -> std::sync::Arc<crate::gate::Permit> {
        self._admission.clone()
    }
    pub(crate) fn temporary(&mut self, length: u64) {
        self.temporary = length;
    }
    pub(crate) fn complete(mut self) {
        self.released = true;
    }
    pub(crate) async fn release(mut self) -> Result<(), Error> {
        let result = tokio::time::timeout(
            Duration::from_secs(6),
            self.store.release(self.key, self.epoch, self.temporary),
        )
        .await
        .map_err(|_| Error::Cleanup)
        .and_then(|value| value);
        // Unconfirmed work remains charged; expiry alone never proves its resources closed.
        self.released = true;
        if result.is_err() {
            tracing::warn!(upload=%self.key, epoch=%self.epoch, "upload lease cleanup unconfirmed");
        }
        result
    }
}
impl Drop for UploadLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let store = self.store.clone();
        let (key, epoch) = (self.key, self.epoch);
        let permit = self.permit.take();
        let temporary = self.temporary;
        let admission = self._admission.clone();
        if tokio::runtime::Handle::try_current().is_ok() {
            self.store.cleanup_tasks.spawn(async move {
                let _permit = permit;
                let _admission = admission;
                if !matches!(tokio::time::timeout(Duration::from_secs(6), store.release(key, epoch, temporary)).await, Ok(Ok(()))) {
                    tracing::warn!(upload=%key, epoch=%epoch, "cancelled upload cleanup unconfirmed");
                }
            });
        } else {
            tracing::warn!(upload=%key, epoch=%epoch, "upload cleanup unavailable; reservation remains fenced");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn stages_share_operation_cutoff() {
        let budget = UploadBudget::new(
            &rss_mdm_audit_integration::budget::RuntimeTimer,
            Duration::from_secs(12),
        )
        .unwrap();
        assert_eq!(
            budget.operation.instant() + Duration::from_secs(3),
            budget.total.instant()
        );
        budget
            .work(async {
                tokio::time::sleep(Duration::from_secs(8)).await;
                Ok::<_, Error>(())
            })
            .await
            .unwrap();
        assert!(matches!(
            budget
                .work(async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok::<_, Error>(())
                })
                .await,
            Err(Error::Deadline)
        ));
    }
}
