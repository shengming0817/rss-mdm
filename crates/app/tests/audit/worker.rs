use super::*;
use anyhow::{Result, ensure};
use rss_mdm_audit_integration::{AuditIntent, AuditStore, Fact, RequestAudit};
use rss_request_context::TenantId;
use sqlx::{Connection, PgConnection};

async fn enqueue(store: &AuditStore, tenant: TenantId, key: &str) -> Result<()> {
    let audit = RequestAudit::new(
        tenant.to_string(),
        "worker_evidence",
        AuditIntent::Management,
    );
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Device, key);
    let fact = Fact::business(&audit, key, key.as_bytes(), 200, "success", None)?;
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
    Ok(())
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
async fn worker_progresses_other_tenants_and_recovers_uncertain_effects() -> Result<()> {
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
        let mut launch = startup.commit();
        launch.stage_task_with_token(listener.clone().registration().critical());
        launch.stage_deferred_task_with_token(worker.clone().registration().critical());
        launch.finish();
        let result = async {
            enqueue(&fixture.audit, tenant, "worker-seed").await?;
            wait_delivered(&mut observer, tenant, "worker-seed").await?;
            let mut blocker = PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
            let mut hold = blocker.begin().await?;
            sqlx::query("SELECT tenant_id FROM rss_audit.heads WHERE tenant_id=$1::uuid FOR UPDATE")
                .bind(tenant.to_string()).fetch_all(&mut *hold).await?;
            let checked = async {
                enqueue(&fixture.audit, tenant, "worker-held").await?;
                enqueue(&management_store, management, "worker-independent").await?;
                wait_delivered(&mut observer, management, "worker-independent").await?;
                ensure!(!delivered(&mut observer, tenant, "worker-held").await?, "fixture must actually block one chain");
                Ok::<_, anyhow::Error>(())
            }.await;
            hold.rollback().await?;
            blocker.close().await?;
            checked?;
            wait_delivered(&mut observer, tenant, "worker-held").await?;
            #[cfg(feature = "integration")]
            worker.delivery.inject_next_projection_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
                std::future::ready(()),
            )?;
            enqueue(&fixture.audit, tenant, "worker-unknown").await?;
            enqueue(&management_store, management, "worker-sibling").await?;
            wait_delivered(&mut observer, tenant, "worker-unknown").await?;
            wait_delivered(&mut observer, management, "worker-sibling").await?;
            #[cfg(feature = "integration")]
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let observed = worker.health.projection.lock().expect("projection health").clone();
                    if observed.is_some_and(|v| v["uncertain_total"].as_u64().unwrap_or(0) > 0 && v["resolved_total"].as_u64().unwrap_or(0) > 0) { break; }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='mdm.business' AND event_id='worker-unknown'")
                .bind(tenant.to_string()).fetch_one(&mut observer).await?;
            ensure!(count == 1, "unknown outcome must not duplicate the effect");
            Ok::<_, anyhow::Error>(())
        }.await;
        let shutdown = owner.shutdown().join().await?;
        ensure!(shutdown.is_clean(), "worker must release original owners: {shutdown:?}");
        observer.close().await?;
        result
    }).await
}
