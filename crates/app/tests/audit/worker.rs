use super::*;
use anyhow::{Result, ensure};
use rss_mdm_audit_integration::{AuditIntent, AuditStore, Fact, RequestAudit};
use rss_request_context::TenantId;
use sqlx::{Connection, PgConnection};

async fn enqueue(store: &AuditStore, tenant: TenantId, key: &str) -> Result<String> {
    let audit = RequestAudit::new(
        tenant.to_string(),
        "worker_evidence",
        AuditIntent::Management,
    );
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Device, key);
    let fact = Fact::business(&audit, key, key.as_bytes(), 200, "success", None)?;
    let event_id = fact.identity().event_id().as_str().to_owned();
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(ACTION_BUDGET);
    let result = store
        .write(
            tenant,
            &budget.source_control(),
            (store, &fact),
            |(store, fact), tx| Box::pin(async move { store.append(tx, fact, false).await }),
        )
        .await;
    let committed = result.fold(
        |_| true,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
    );
    audit.finalize(None);
    ensure!(
        committed,
        "fixture source must commit before testing projection"
    );
    Ok(event_id)
}
async fn delivered(observer: &mut PgConnection, tenant: TenantId, key: &str) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_audit.receipts r JOIN rss_transactional_messaging.outbox o ON (o.tenant_id,o.message_id)=(r.tenant_id,r.message_id) JOIN rss_transactional_messaging.inbox i ON (i.tenant_id,i.message_id)=(r.tenant_id,r.message_id) AND i.consumer_group='mdm.audit.v1' JOIN rss_audit.records a ON (a.tenant_id,a.source_id,a.event_id)=(r.tenant_id,r.source_id,r.event_id) WHERE r.tenant_id=$1::uuid AND r.event_id=$2 AND r.projected_at IS NOT NULL AND o.status='published' AND i.disposition='succeeded')")
        .bind(tenant.to_string()).bind(key).fetch_one(observer).await?)
}
async fn wait_delivered(observer: &mut PgConnection, tenant: TenantId, key: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !delivered(observer, tenant, key).await? {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.worker: actual host batch worker, source NOTIFY, tenant chain contention and uncertainty"]
async fn worker_progresses_siblings_before_a_blocked_effect_and_resolves_uncertainty() -> Result<()>
{
    let mut fixture = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let config: Config = serde_json::from_value(fixture.base.clone())?;
        let tenant = fixture.identity.tenant;
        let management = fixture.identity.management_tenant;
        let mut observer = PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let management_store = crate::audit_integration_tests::new_store(fixture.pool.clone(), config.audit.integrity()?, management).await?;
        let listener = crate::worker_wake::Listener::new(config.access_options()?, tenant)
            .with_identity(fixture.identity.instance, [tenant, management]);
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(40))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut startup = owner.startup()?;
        startup.stage_resource(DynManagedResource::new_box(listener.clone()));
        let worker = Worker::open(&config, listener.signals.mdm_audit.clone(), |r| startup.stage_resource(r)).await?;
        // Preparation only: the assertions below are exclusively driven by the production worker.
        crate::audit_test_support::projection::drain(tenant, config.audit.integrity()?).await?;
        crate::audit_test_support::projection::drain(management, config.audit.integrity()?).await?;
        // Provider claims one tenant batch at a time. Use two independent resource partitions
        // within that batch, then separately verify the next tenant is served.
        let first_id = enqueue(&fixture.audit, tenant, "worker-unknown").await?;
        let second_id = enqueue(&fixture.audit, tenant, "worker-sibling").await?;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        worker.recovery_fault.store(true, std::sync::atomic::Ordering::Release);
        let second_fault = worker.clone();
        worker.delivery.inject_next_projection_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            async move {
                second_fault.delivery.inject_next_projection_fault(
                    rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
                    async {},
                ).expect("second effect fault");
                let _ = entered.send(()); let _ = released.await;
            },
        )?;
        let mut launch = startup.commit();
        launch.stage_task_with_token(listener.clone().registration().critical());
        launch.stage_deferred_task_with_token(worker.clone().registration().critical());
        launch.finish();
        let result = async {
            // The first actual effect cannot acquire its connection until released. A serial
            // implementation cannot deliver either sibling during this barrier, even by reordering.
            let concurrent = async {
                tokio::time::timeout(ACTION_BUDGET, started).await??;
                tokio::time::timeout(ACTION_BUDGET / 2, async {
                    loop {
                        let first = delivered(&mut observer, tenant, &first_id).await?;
                        let second = delivered(&mut observer, tenant, &second_id).await?;
                        if first || second { ensure!(first != second, "paused effect unexpectedly completed"); break; }
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Ok::<_, anyhow::Error>(())
                }).await??;
                Ok::<_, anyhow::Error>(())
            }.await;
            let _ = release.send(());
            concurrent?;
            wait_delivered(&mut observer, tenant, &first_id).await?;
            wait_delivered(&mut observer, tenant, &second_id).await?;
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let observed = worker.health.projection.lock().expect("projection health").clone();
                    if observed.is_some_and(|v| v["uncertain_total"] == 2 && v["resolved_total"] == 1 && v["pending_recovery"] == 1) { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await?;
            // Only the failed recovery occupies capacity. A new event can finish before it retries.
            let new_id = enqueue(&fixture.audit, tenant, "worker-after-recovery-failure").await?;
            wait_delivered(&mut observer, tenant, &new_id).await?;
            ensure!(worker.health.projection.lock().expect("projection health").as_ref().is_some_and(|v| v["pending_recovery"] == 1), "new delivery waited for the unrelated recovery retry");
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let observed = worker.health.projection.lock().expect("projection health").clone();
                    if observed.is_some_and(|v| v["resolved_total"] == 2 && v["pending_recovery"] == 0) { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='mdm.business' AND event_id=$2")
                .bind(tenant.to_string()).bind(&first_id).fetch_one(&mut observer).await?;
            ensure!(count == 1, "unknown outcome must not duplicate the effect");
            let management_id = enqueue(&management_store, management, "worker-next-tenant").await?;
            wait_delivered(&mut observer, management, &management_id).await?;
            Ok::<_, anyhow::Error>(())
        }.await;
        let shutdown = owner.shutdown().join().await?;
        ensure!(shutdown.is_clean(), "worker must release original owners: {shutdown:?}");
        observer.close().await?;
        result
    }).await
}
