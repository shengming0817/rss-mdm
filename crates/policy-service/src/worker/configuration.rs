//! Configuration participates in the existing Policy runner and its global concurrency budget.
use super::*;
impl PolicyWork {
    pub(super) async fn observe_configuration<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<ReconcileDiff<bool>>, rss_reconcile::Error> {
        control.check()?;
        let service = self
            .service
            .configuration
            .as_ref()
            .ok_or_else(|| reconcile_error(Error::Unsupported))?;
        let pending = crate::transaction::inspect_budget(
            &self.service.runtime,
            self.service.tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                control.remaining(),
            ),
            (service, claim.target().entity()),
            |ctx, tx| Box::pin(async move { ctx.0.work_pending_in(tx, ctx.1).await }),
        )
        .await
        .map_err(reconcile_error)?;
        Ok(ReconcileStep::Ready(ReconcileDiff::between(
            DesiredState::present(false),
            ActualState::present(pending),
        )))
    }
    pub(super) async fn apply_configuration<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, rss_reconcile::Error> {
        control.check()?;
        let service = self
            .service
            .configuration
            .as_ref()
            .ok_or_else(|| reconcile_error(Error::Unsupported))?;
        if claim.target().entity() == "configuration-relay" {
            // The RSS outbox claim and idempotent gateway receipt protect this independent relay.
            let count = service.relay_once(control).await.map_err(reconcile_error)?;
            return Ok(if count == 0 {
                ReconcileStep::Deferred(crate::worker_wake::RECOVERY)
            } else {
                ReconcileStep::Ready(())
            });
        }
        let cut = if claim.target().entity() == "configuration-inputs" {
            let budget = rss_mdm_audit_integration::budget::AuditBudget::new(control.remaining());
            Some(
                rss_mdm_inventory_service::assets::cut::capture(
                    &self.service.audit_store,
                    self.service.tenant,
                    &budget,
                )
                .await
                .map_err(|_| reconcile_error(Error::Unavailable(Failure::PolicyStorage)))?,
            )
        } else {
            None
        };
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            self.profile(),
            self.service.tenant.to_string(),
            "configuration_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("configuration-policy");
        let result = crate::transaction::run_budget(
            &self.service.audit_store,
            &self.service.runtime,
            self.service.tenant,
            &audit,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                control.remaining(),
            ),
            (service, claim, cut.as_ref(), &audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, claim, cut, audit) = *ctx;
                    let entity = claim.target().entity();
                    let device = match service.prepare_work_in(tx, entity, audit).await? {
                        ReconcileStep::Ready(device) => device,
                        ReconcileStep::Deferred(after) => {
                            return Ok(ReconcileStep::Deferred(after));
                        }
                    };
                    let resources = match &device {
                        Some(device) => rss_mdm_registration_service::lifecycle::resources::device(
                            tx.tenant_id(),
                            device,
                            rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
                        ),
                        None => rss_reconcile::ResourceSet::empty(tx.tenant_id()),
                    };
                    service
                        .reconcile_messaging
                        .bind_in(tx, claim.target(), &resources)
                        .await?;
                    let rejected = Mutex::new(None);
                    let result = service
                        .reconcile_messaging
                        .protect_in(
                            tx,
                            claim,
                            (service, entity, device, cut, audit, &rejected),
                            |ctx, tx| {
                                Box::pin(async move {
                                    ctx.0
                                        .advance_work_in(tx, ctx.1, ctx.2.as_ref(), ctx.3, ctx.4)
                                        .await
                                        .map(ProtectedStep::Ready)
                                        .map_err(|e| fault(e, ctx.5))
                                })
                            },
                        )
                        .await;
                    match result {
                        Ok(step) => Ok(step),
                        Err(e) => Err(rejected
                            .into_inner()
                            .expect("configuration rejection")
                            .map(crate::transaction::Fault::Request)
                            .unwrap_or(crate::transaction::Fault::Storage(e))),
                    }
                })
            },
        )
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result.map_err(reconcile_error)
    }
}
