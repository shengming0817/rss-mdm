//! Exercise real Device claims and fenced transactions with a finite correctness fixture.
use rss_mdm_device_service::{Associations, Error};
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
    /// Let RSS settle the real input and device targets, including retryable fences.
    pub async fn drain(&self) -> Result<usize, Error> {
        let before = self.count().await?;
        let mut running = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(40))
                .map_err(|_| Error::Storage)?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )
        .map_err(|_| Error::Storage)?;
        let mut launch = running.startup().map_err(|_| Error::Storage)?.commit();
        launch.stage_deferred_task_with_token(
            self.work
                .clone()
                .registration(Arc::new(tokio::sync::Notify::new())),
        );
        launch.finish();
        let result = tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                let tenant = self.tenant.to_string();
                let settled = self.runtime.local_tx(self.tenant,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6)),
                    move |tx| Box::pin(async move {
                        tx.with_connection(move |c| Box::pin(async move {
                            sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM mdm_devices.checkpoints p WHERE p.tenant_id=$1::uuid AND NOT p.rebuilding AND p.consumed>=coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=p.tenant_id),0)) AND NOT EXISTS(SELECT FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND requested>completed)")
                                .bind(tenant).fetch_one(c).await
                        })).await
                    })).await.fold(Ok, |_| Err(Error::Storage), |_| Err(Error::Storage), |_| Err(Error::RollbackFailed), |_| Err(Error::CommitUnknown), |_| Err(Error::Deadline))?;
                if settled { return self.count().await; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.map_err(|_| Error::Deadline).and_then(|result| result);
        let stopped = running
            .shutdown()
            .join()
            .await
            .map_err(|_| Error::Storage)?;
        if !stopped.is_clean() {
            return Err(Error::Storage);
        }
        Ok(result?.saturating_sub(before) as usize)
    }
    async fn count(&self) -> Result<i64, Error> {
        let tenant = self.tenant.to_string();
        self.runtime.local_tx(self.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6)),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT count(*) FROM mdm_devices.operations WHERE tenant_id=$1::uuid AND actor='device-associations'").bind(tenant).fetch_one(c).await})).await
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|_|Err(Error::Deadline))
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
