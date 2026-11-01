//! Transparent observations of actual provider results, including confirmed empty scans.
use super::Readiness;
use rss_reconcile::{
    Claim, ClaimBatch, Completion, Control, DurableStore, Error, ResourceSet, Scope, Target, Timer,
};
use std::time::Duration;

pub struct ObservedStore<'a, S> {
    store: &'a S,
    readiness: &'a Readiness,
}
impl<'a, S> ObservedStore<'a, S> {
    pub fn new(store: &'a S, readiness: &'a Readiness) -> Self {
        Self { store, readiness }
    }
}
impl<S: DurableStore> DurableStore for ObservedStore<'_, S> {
    type Claim = S::Claim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.readiness.check(target.scope())?;
        self.store.wake(target, resources, control).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.readiness.check(target.scope())?;
        self.store.bind_resources(target, resources, control).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<ClaimBatch<Self::Claim>, Error> {
        self.readiness.check(scope)?;
        let result = self.store.claim_due(scope, limit, lease, control).await;
        self.readiness
            .scan(result.as_ref().map(|_| ()).map_err(|e| e.kind()));
        result
    }
    async fn renew<T: Timer>(
        &self,
        claim: &Self::Claim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.readiness.check(claim.target().scope())?;
        self.store.renew(claim, lease, control).await
    }
    async fn release<T: Timer>(
        &self,
        claim: &Self::Claim,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.readiness.check(claim.target().scope())?;
        self.store.release(claim, control).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &Self::Claim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.readiness.check(claim.target().scope())?;
        let result = self.store.finish(claim, completion, control).await;
        if result.is_ok() {
            self.readiness.settled(claim.target(), completion);
        }
        result
    }
}
