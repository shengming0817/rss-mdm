//! Per-host limits for channel and source workers. Object exclusivity is independent of tuning.
use std::num::NonZeroUsize;
use uuid::Uuid;

pub fn fair_share(total: NonZeroUsize) -> usize {
    total.get().saturating_sub(1).max(1)
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub total: NonZeroUsize,
    resource: NonZeroUsize,
}
impl Limits {
    pub fn new(total: NonZeroUsize, resource: NonZeroUsize) -> Option<Self> {
        (total.get() <= tokio::sync::Semaphore::MAX_PERMITS && resource.get() <= fair_share(total))
            .then_some(Self { total, resource })
    }
    pub fn source_quotas<R, O>(
        &self,
        tenant: Uuid,
        resource: R,
        object: O,
    ) -> [(Group<R, O>, usize); 3] {
        [
            (Group::Tenant(tenant), fair_share(self.total)),
            (Group::Resource(resource), self.resource.get()),
            (Group::Object(object), 1),
        ]
    }
    pub fn push_quotas<R: Clone, O>(
        &self,
        tenant: Uuid,
        resource: R,
        object: O,
    ) -> [(Group<R, O>, usize); 4] {
        let [global_tenant, provider, channel] =
            self.source_quotas(tenant, resource.clone(), object);
        [
            global_tenant,
            provider,
            (
                Group::TenantResource(tenant, resource),
                fair_share(self.resource),
            ),
            channel,
        ]
    }
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub enum Group<R, O> {
    Tenant(Uuid),
    Resource(R),
    TenantResource(Uuid, R),
    Object(O),
}
