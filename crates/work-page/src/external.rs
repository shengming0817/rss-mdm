//! Explicit per-host provider/source ceilings. Tenant fairness follows ready work.
use super::Work;
use std::num::NonZeroUsize;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub total: NonZeroUsize,
    resource: NonZeroUsize,
}

impl Limits {
    pub fn new(total: NonZeroUsize, resource: NonZeroUsize) -> Option<Self> {
        (total.get() <= tokio::sync::Semaphore::MAX_PERMITS && resource <= total)
            .then_some(Self { total, resource })
    }

    pub fn work<R, O>(&self, tenant: Uuid, resource: R, object: O) -> Work<Uuid, R, O> {
        Work {
            tenant,
            resource,
            resource_limit: self.resource.get(),
            object,
        }
    }
}
