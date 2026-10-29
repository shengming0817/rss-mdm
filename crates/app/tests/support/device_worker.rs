//! Exercise real Device claims and fenced transactions with a finite correctness fixture.
use rss_mdm_device_service::{Associations, Error};
use rss_reconcile::{Completion, Control, DurableStore, Reconciler, Scope, Target};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use std::{sync::Arc, time::Duration};
#[derive(Clone)]
pub(crate) struct DeviceOwner {
    pub service: Arc<Associations>,
    pub work: Arc<rss_mdm_device_service::worker::DeviceWork>,
    pub runtime: Arc<PgRuntime>,
    pub scheduler: crate::scheduler::SchedulerStorage,
    tenant: TenantId,
}
impl std::ops::Deref for DeviceOwner {
    type Target = Associations;
    fn deref(&self) -> &Associations {
        &self.service
    }
}
impl DeviceOwner {
    pub async fn new(
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
    ) -> anyhow::Result<Self> {
        let scheduler = crate::scheduler::SchedulerStorage::open(
            crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
        )
        .await?;
        let service = Arc::new(Associations::new(audit, tenant, &[7; 32])?);
        let work = Arc::new(
            rss_mdm_device_service::worker::DeviceWork::new(
                service.clone(),
                runtime.clone(),
                scheduler.store.clone(),
                Arc::new(crate::registration_lifecycle::Bridge),
                4,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    Duration::from_secs(8),
                ),
            )
            .await?,
        );
        Ok(Self {
            service,
            work,
            runtime,
            scheduler,
            tenant,
        })
    }
    /// Production observe/apply/finish boundaries; no owner business implementation is repeated.
    pub async fn drain(&self) -> Result<usize, Error> {
        let timer = rss_mdm_execution_service::recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = Control::new(&timer, Duration::from_secs(40), &cancel);
        let scope = Scope::new(self.tenant, "mdm.devices").map_err(|_| Error::Storage)?;
        let before = self.count().await?;
        for name in ["inputs", "retirements"] {
            self.work
                .wake(
                    &Target::new(scope.clone(), name).map_err(|_| Error::Storage)?,
                    &control,
                )
                .await
                .map_err(project)?;
        }
        loop {
            control.check().map_err(project)?;
            let mut claims = self
                .work
                .claim_due(&scope, 4, Duration::from_secs(30), &control)
                .await
                .map_err(project)?;
            if claims.is_empty() {
                break;
            }
            claims.sort_by_key(|c| match c.target().entity() {
                "retirements" => 0,
                "inputs" => 1,
                _ => 2,
            });
            let mut discovered = false;
            for claim in claims {
                if discovered && claim.target().entity().starts_with("work:") {
                    self.work.release(&claim, &control).await.map_err(project)?;
                    continue;
                }
                let diff = match self.work.observe(&claim, &control).await {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = self.work.release(&claim, &control).await;
                        return Err(project(e));
                    }
                };
                if diff.actual().as_ref() == Some(&true) {
                    if let Err(e) = self.work.apply(&claim, diff, &control).await {
                        let _ = self.work.release(&claim, &control).await;
                        return Err(project(e));
                    }
                    discovered |= claim.target().entity() == "inputs";
                    self.work
                        .finish(&claim, Completion::Reobserve(Duration::ZERO), &control)
                        .await
                        .map_err(project)?;
                } else {
                    self.work
                        .finish(&claim, Completion::Converged, &control)
                        .await
                        .map_err(project)?;
                }
            }
        }
        Ok(self.count().await?.saturating_sub(before) as usize)
    }
    async fn count(&self) -> Result<i64, Error> {
        let tenant = self.tenant.to_string();
        self.runtime.local_tx(self.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6)),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT count(*) FROM mdm_devices.operations WHERE tenant_id=$1::uuid AND actor='device-associations'").bind(tenant).fetch_one(c).await})).await
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|_|Err(Error::Deadline))
    }
}
fn project(error: rss_reconcile::Error) -> Error {
    match error.kind() {
        rss_reconcile::ErrorKind::CommitUnknown => Error::CommitUnknown,
        rss_reconcile::ErrorKind::RollbackFailed => Error::RollbackFailed,
        rss_reconcile::ErrorKind::Deadline => Error::Deadline,
        _ => Error::Storage,
    }
}
/// Standalone consumer fixture; all acquired resources are drained before returning.
pub(crate) async fn drain(
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: TenantId,
) -> anyhow::Result<usize> {
    let (pool, runtime, _) = crate::audit_test_support::request_store().await?;
    let mut resources = super::runtime::Resources::default();
    resources.resource(super::runtime::PoolResource(pool));
    resources.resource(super::runtime::SourceResource(runtime.clone()));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
    let audit = Arc::new(
        audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let owner = DeviceOwner::new(audit, runtime, tenant).await?;
    resources.resource(owner.scheduler.clone());
    let result = owner.drain().await;
    resources.finish(async { Ok(result?) }).await
}
