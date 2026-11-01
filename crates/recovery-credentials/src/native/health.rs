//! Owner-specific settlement policy; common observations live in recovery-observation.
use rss_reconcile::ErrorKind;
// Transparent observations of real claim results, including confirmed empty scans.
pub(super) struct ObservedStore<'a>(pub &'a super::Service);
impl rss_reconcile::DurableStore for ObservedStore<'_> {
    type Claim = rss_reconcile_postgres::PgClaim;
    async fn wake<T: rss_reconcile::Timer>(
        &self,
        target: &rss_reconcile::Target,
        resources: &rss_reconcile::ResourceSet,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        self.0.reconcile.wake(target, resources, control).await
    }
    async fn bind_resources<T: rss_reconcile::Timer>(
        &self,
        target: &rss_reconcile::Target,
        resources: &rss_reconcile::ResourceSet,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        self.0
            .reconcile
            .bind_resources(target, resources, control)
            .await
    }
    async fn claim_due<T: rss_reconcile::Timer>(
        &self,
        scope: &rss_reconcile::Scope,
        limit: usize,
        lease: std::time::Duration,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<rss_reconcile::ClaimBatch<Self::Claim>, rss_reconcile::Error> {
        rss_mdm_recovery_observation::ObservedStore::new(&self.0.reconcile, &self.0.readiness)
            .claim_due(scope, limit, lease, control)
            .await
    }
    async fn renew<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        lease: std::time::Duration,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        self.0.reconcile.renew(claim, lease, control).await
    }
    async fn release<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        self.0.reconcile.release(claim, control).await
    }
    async fn finish<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        completion: rss_reconcile::Completion,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        use rss_reconcile::Completion;
        let settlement = control.child(std::time::Duration::from_secs(6));
        let scheduled = if matches!(completion, Completion::Reobserve(_)) {
            let pending = crate::native::transaction::inspect(
                &self.0.transactions.runtime,
                self.0.transactions.tenant,
                claim.target().entity(),
                |entity, tx| {
                    Box::pin(async move { crate::native::recovery::backlog_in(tx, entity).await })
                },
            )
            .await
            .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
            Completion::Reobserve(std::time::Duration::from_millis(if pending {
                20
            } else {
                5000
            }))
        } else {
            completion
        };
        rss_mdm_recovery_observation::ObservedStore::new(&self.0.reconcile, &self.0.readiness)
            .finish(claim, scheduled, &settlement)
            .await
    }
}
