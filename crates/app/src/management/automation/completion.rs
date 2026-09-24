//! Compose the RSS terminal scheduling decision with the product task result.
//! ref: rss crates/reconcile/src/ports.rs, crates/reconcile-postgres/src/messaging.rs@ec67bd142d70cb8f0d56feae636ac9471e7471fc
use super::*;
use rss_reconcile::{
    Completion, Control, DurableStore, Error as ReconcileError, ErrorKind, Scope, Target, Timer,
};
use rss_reconcile_postgres::PgClaim;
impl DurableStore for Automation {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.store.wake(target, control).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<Vec<PgClaim>, ReconcileError> {
        self.store.claim_due(scope, limit, lease, control).await
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.store.renew(claim, lease, control).await
    }
    async fn release<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.store.release(claim, control).await
    }
    fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> impl std::future::Future<Output = std::result::Result<(), ReconcileError>> + Send {
        Box::pin(async move {
            if matches!(completion, Completion::Suspended { .. })
                || (completion == Completion::Converged && claim.target().entity() == "changes")
            {
                let entity = claim.target().entity();
                let id = entity
                    .strip_prefix("job:")
                    .and_then(|s| Uuid::parse_str(s).ok());
                if id.is_none() && entity != "changes" {
                    return Err(ReconcileError::new(ErrorKind::Invariant));
                }
                self.service
                    .runtime
                    .local_tx_with_context(
                        self.service.tenant,
                        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                            control.remaining(),
                        ),
                        (&self.service, claim, &self.service),
                        |(service, claim, context), tx| {
                            Box::pin(async move {
                                service
                                    .audit_store
                                    .lock_in(tx)
                                    .await
                                    .map_err(PgError::from)?;
                                rss_reconcile_postgres::messaging::protect_in(
                                    tx,
                                    claim,
                                    context,
                                    |service, tx| {
                                        Box::pin(async move {
                                            let result = match id {
                                Some(id) => {
                                    crate::management::automation::jobs::finish_job_in(
                                        tx, &service.audit_store,
                                        id,
                                        Some("automation_suspended"),
                                    )
                                    .await
                                }
                                None if completion == Completion::Converged => {
                                    service.clear_ingress_failure_in(tx).await
                                }
                                None => service.fail_ingress_in(tx).await,
                            };
                                            result.map_err(|e| fault(e, &Mutex::new(None)))
                                        })
                                    },
                                )
                                .await
                            })
                        },
                    )
                    .await
                    .fold(
                        Ok,
                        |_| Err(ReconcileError::new(ErrorKind::Transient)),
                        |_| Err(ReconcileError::new(ErrorKind::Transient)),
                        |_| Err(ReconcileError::new(ErrorKind::CommitUnknown)),
                        |_| Err(ReconcileError::new(ErrorKind::CommitUnknown)),
                        |_| Err(ReconcileError::new(ErrorKind::Transient)),
                    )?;
            }
            self.store.finish(claim, completion, control).await?;
            if let Completion::Suspended { failures } = completion {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"mdm_automation_terminal_attempt","target":claim.target().entity(),"failures":failures})
                );
            }
            Ok(())
        })
    }
}

impl Management {
    pub(crate) async fn ingress_ready(&self) -> bool {
        self.runtime.local_tx(self.tenant,deadline(),|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_management.asset_dispatch WHERE tenant_id=$1::uuid AND failure IS NOT NULL)").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(|ready|ready, |_|false, |_|false, |_|false, |_|false, |_|false)
    }
    pub(in crate::management::automation) async fn clear_ingress_failure_in(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_management.asset_dispatch SET failure=NULL WHERE tenant_id=$1::uuid AND failure IS NOT NULL").bind(tenant).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    async fn fail_ingress_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        let generation: Option<i64> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("INSERT INTO mdm_management.asset_dispatch(tenant_id,failure,failure_generation) VALUES($1::uuid,'automation_suspended',1) ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure,failure_generation=asset_dispatch.failure_generation+1 WHERE asset_dispatch.failure IS NULL RETURNING failure_generation")
                .bind(tenant).fetch_optional(c).await
        })).await?;
        if let Some(generation) = generation {
            let audit = RequestAudit::new(self.tenant.to_string(), "automation_failed");
            audit.identify_service("service:asset-automation");
            audit.target("asset_ingress");
            let fact = rss_mdm_audit_integration::Fact::business(
                &audit,
                &format!("asset-ingress:{generation}:failed"),
                &generation.to_be_bytes(),
                200,
                "failed",
                None,
            )
            .map_err(|_| Error::Unavailable(Failure::Audit))?;
            let result = self
                .audit_store
                .append_in(tx, &fact, false)
                .await
                .map_err(Error::from);
            audit.finalize(None);
            result?;
        }
        Ok(())
    }
}
