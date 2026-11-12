//! Owner-specific settlement policy; common observations live in recovery-observation.
use rss_reconcile::ErrorKind;
// Transparent observations of real claim results, including confirmed empty scans.
pub(super) struct ObservedStore<'a>(pub &'a super::SoftwareService);
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
        if self.0.readiness.health().inputs == Some(rss_mdm_recovery_observation::Phase::Initializing) {
            let suspended = crate::deployment::transaction::inspect(
                &self.0.transactions.runtime,
                self.0.transactions.tenant,
                (),
                |_, tx| Box::pin(async move {
                    crate::deployment::source_changes::health_in(tx).await.map(|(_, _, suspended)| suspended)
                }),
            ).await.map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
            self.0.readiness.inputs(if suspended { Err(ErrorKind::Transient) } else { Ok(()) });
        }
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
    #[expect(
        clippy::cognitive_complexity,
        reason = "claim settlement and owner readiness must interpret every reconcile outcome together"
    )]
    async fn finish<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        completion: rss_reconcile::Completion,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        use rss_reconcile::Completion;
        let settlement = control.child(std::time::Duration::from_secs(6));
        let input = claim.target()
            == &crate::deployment::source_changes::target(self.0.transactions.tenant);
        if input
            && matches!(
                self.0.settle_inputs(claim, completion, &settlement).await?,
                rss_reconcile::ReconcileStep::Deferred(_)
            )
        {
            return Err(rss_reconcile::Error::new(ErrorKind::BindingChanged));
        }
        let scheduled = if let Some(work) =
            crate::deployment::actions::scheduled::Work::parse(claim.target().entity())
        {
            if matches!(completion, Completion::Converged | Completion::Reobserve(_)) {
                let delay = crate::deployment::transaction::inspect(
                    &self.0.transactions.runtime,
                    self.0.transactions.tenant,
                    (self.0, work),
                    |(service, work), tx| {
                        Box::pin(async move {
                            crate::deployment::actions::scheduled::delay_in(service, tx, work).await
                        })
                    },
                )
                .await
                .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
                delay.map_or(Completion::Converged, Completion::Reobserve)
            } else {
                completion
            }
        } else if let Some(work @ crate::deployment::actions::run_recovery::Work::Run(_)) =
            crate::deployment::actions::run_recovery::Work::parse(claim.target().entity())
            && completion == Completion::Converged
        {
            let waiting = crate::deployment::transaction::inspect(
                &self.0.transactions.runtime,
                self.0.transactions.tenant,
                work,
                |work, tx| {
                    Box::pin(async move {
                        crate::deployment::actions::run_recovery::active(tx, *work).await
                    })
                },
            )
            .await
            .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
            if waiting {
                Completion::Reobserve(std::time::Duration::from_secs(5))
            } else {
                Completion::Converged
            }
        } else if let Some(policy) =
            crate::deployment::actions::recovery::policy_id(claim.target().entity())
            && matches!(completion, Completion::Reobserve(_))
        {
            let pending = crate::deployment::transaction::inspect(
                &self.0.transactions.runtime,
                self.0.transactions.tenant,
                policy,
                |policy, tx| {
                    Box::pin(async move {
                        crate::deployment::actions::recovery::backlog_in(tx, *policy).await
                    })
                },
            )
            .await
            .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
            Completion::Reobserve(if pending {
                std::time::Duration::from_millis(20)
            } else {
                std::time::Duration::from_secs(5)
            })
        } else {
            match (input, completion) {
                (false, Completion::Reobserve(_)) => {
                    let pending = crate::deployment::transaction::inspect(
                        &self.0.transactions.runtime,
                        self.0.transactions.tenant,
                        claim.target().entity(),
                        |entity, tx| {
                            Box::pin(async move {
                                crate::deployment::recovery::backlog_in(tx, entity).await
                            })
                        },
                    )
                    .await
                    .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
                    Completion::Reobserve(if pending {
                        std::time::Duration::from_millis(20)
                    } else {
                        std::time::Duration::from_secs(5)
                    })
                }
                _ => completion,
            }
        };
        let result =
            rss_mdm_recovery_observation::ObservedStore::new(&self.0.reconcile, &self.0.readiness)
                .finish(claim, scheduled, &settlement)
                .await;
        if input {
            let healthy = result.is_ok()
                && matches!(completion, Completion::Converged | Completion::Reobserve(_));
            self.0.readiness.inputs(if healthy {
                Ok(())
            } else {
                Err(result
                    .as_ref()
                    .err()
                    .map_or(ErrorKind::Transient, |e| e.kind()))
            });
        }
        result
    }
}
