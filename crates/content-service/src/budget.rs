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
    pub(crate) async fn cleanup<T>(
        self,
        future: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let remaining = self.remaining().min(Duration::from_secs(6));
        tokio::time::timeout(remaining, future)
            .await
            .map_err(|_| Error::Cleanup)?
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
    budget: UploadBudget,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    released: bool,
}
impl UploadLease {
    pub(crate) fn new(
        store: &Store,
        key: uuid::Uuid,
        epoch: uuid::Uuid,
        budget: UploadBudget,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Self {
        Self {
            store: store.clone(),
            key,
            epoch,
            budget,
            permit: Some(permit),
            released: false,
        }
    }
    pub(crate) fn complete(mut self) {
        self.released = true;
    }
    pub(crate) async fn release(mut self) -> Result<(), Error> {
        let result = self
            .budget
            .cleanup(self.store.release(self.key, self.epoch))
            .await;
        // A failed bounded release remains fenced until its persisted expiry; don't spin/retry.
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
        let (key, epoch, budget) = (self.key, self.epoch, self.budget);
        let permit = self.permit.take();
        if tokio::runtime::Handle::try_current().is_ok() {
            self.store.cleanup_tasks.spawn(async move {
                let _permit = permit;
                if budget.cleanup(store.release(key, epoch)).await.is_err() {
                    tracing::warn!(upload=%key, epoch=%epoch, "cancelled upload cleanup unconfirmed");
                }
            });
        } else {
            tracing::warn!(upload=%key, epoch=%epoch, "upload cleanup unavailable; lease expiry fences recovery");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn stages_share_cutoff_and_cleanup_uses_only_reserved_time() {
        let budget = UploadBudget::new(
            &rss_mdm_audit_integration::budget::RuntimeTimer,
            Duration::from_secs(12),
        )
        .unwrap();
        assert_eq!(
            budget
                .total
                .instant()
                .duration_since(budget.operation.instant()),
            Duration::from_secs(3)
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
        budget
            .cleanup(async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            budget
                .cleanup(async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(())
                })
                .await,
            Err(Error::Cleanup)
        ));
    }
}
