#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::execution::test_support::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_execution_service::*;
use serde_json::{Value, json};
use sqlx::Connection;
#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.recovery"]
async fn expiry_worker_and_fatal_storage_diagnostic() -> anyhow::Result<()> {
    if let Some(output) = crate::test_support::process::captured_test(
        concat!(
            module_path!(),
            "::expiry_worker_and_fatal_storage_diagnostic"
        ),
        Duration::from_secs(90),
    )
    .await?
    {
        let stderr = String::from_utf8(output.stderr)?;
        ensure!(
            stderr
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .any(|item| item["event"] == "mdm_command_recovery_failure"
                    && item["phase"] == "runner"
                    && item["reason"] == "StorageContract"),
            "missing fatal recovery diagnostic: {stderr}"
        );
        return Ok(());
    }
    let clock = Arc::new(rss_device_command_postgres::IntegrationClock::new(
        1_000_000_000_000,
    )?);
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Controlled(
        clock.clone(),
    ))
    .await?;
    client.expiry_recovery(clock).await?;
    host.close().await?;
    Ok(())
}
#[cfg(feature = "integration")]
impl Client {
    async fn expiry_recovery(
        &mut self,
        clock: Arc<rss_device_command_postgres::IntegrationClock>,
    ) -> anyhow::Result<()> {
        self.set_authorized(true).await?;
        let expiry = Uuid::new_v4();
        let expires_at = clock.now() / 1_000_000 + 1;
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":expiry,"inputVersion":"1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./DevInfo/Mod","instance":[],"operation":"get","value":null}}},"deadline":expires_at}))).await?.0==StatusCode::ACCEPTED);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let config = crate::test_support::identity::config(case_tenant())?;
        let restarted = Box::pin(crate::execution_assembly::open(
            &config,
            config.native_protector()?,
            crate::test_support::identity::audit_store(&config).await?,
            crate::execution_assembly::open_content(&config, config.native_protector()?)?,
            std::collections::BTreeMap::new(),
            rss_device_command_postgres::CommandClock::Controlled(clock.clone()),
        ))
        .await?;
        eprintln!("command T2: restarted runtime admitted");
        let persisted: (String, String) = sqlx::query_as(
            "SELECT c.status,o.status FROM rss_device_command.commands c JOIN rss_transactional_messaging.outbox o ON o.tenant_id=c.tenant_id AND o.message_id=c.outbox_message_id WHERE c.tenant_id=$1::uuid AND c.command_id=$2",
        ).bind(case_tenant()).bind(expiry.to_string()).fetch_one(&mut pg).await?;
        ensure!(persisted == ("queued".into(), "pending".into()));
        clock.advance_to(expires_at * 1_000_000)?;
        let timer = recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(2), &cancel);
        let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: 1,
            lease_ttl: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(1),
            scan_interval: Duration::from_millis(100),
            idle_scan_interval: Duration::from_millis(100),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            max_attempts: 3,
        })?;
        let scope = recovery_scope(restarted.tenant);
        let report = restarted
            .run_recovery(&scope, policy, &control, &tokio::sync::Notify::new())
            .await?;
        ensure!(
            report.execution_failed == 0 && report.suspended == 0,
            "recovery did not complete {:?}",
            report
        );
        let read = self
            .call(Method::GET, &format!("/{}", expiry), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "timed_out" && read.1["observation"]["result"] == "unknown",
            "expiry or unknown effect lost {:?}",
            read
        );
        // Empty discovery defers structural checks. Make an actual operation due
        // before corrupting the catalog, so the worker must reject its claim.
        let wake_timer = recovery::Timer::new();
        let wake_control =
            rss_reconcile::Control::new(&wake_timer, Duration::from_secs(2), &cancel);
        rss_reconcile::DurableStore::wake(
            &restarted.reconcile,
            &rss_mdm_execution_service::target(restarted.tenant, case_device()),
            &wake_control,
        )
        .await?;
        sqlx::raw_sql("COMMENT ON SCHEMA rss_reconcile IS 'damaged'")
            .execute(&mut pg)
            .await?;
        let fatal_timer = recovery::Timer::new();
        let fatal_control =
            rss_reconcile::Control::new(&fatal_timer, Duration::from_secs(2), &cancel);
        let fatal = restarted
            .run_recovery(&scope, policy, &fatal_control, &tokio::sync::Notify::new())
            .await;
        sqlx::raw_sql("COMMENT ON SCHEMA rss_reconcile IS 'rss-reconcile-postgres:1'")
            .execute(&mut pg)
            .await?;
        ensure!(
            fatal.is_err_and(|error| error.kind() == rss_reconcile::ErrorKind::StorageContract),
            "fatal storage contract was not propagated"
        );
        // Exercise the same unbounded worker entry used by the runtime registration.
        // The expired operation has not been published; an autonomous relay must progress
        // without reviving the command, then stop via its normal cancellation signal.
        let message_id = format!("dispatch.{}", expiry);
        let pending: String = sqlx::query_scalar(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(&message_id)
        .fetch_one(&mut pg)
        .await?;
        ensure!(pending == "pending");
        let worker_cancel = tokio_util::sync::CancellationToken::new();
        let signals = crate::worker_wake::Signals::default();
        let flow_signals = signals.flow();
        let mut worker = Box::pin(restarted.run_worker(&worker_cancel, &flow_signals));
        tokio::select! {
            outcome=&mut worker => anyhow::bail!("production worker exited before publication: {outcome:?}"),
            observed=tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let status:String=sqlx::query_scalar("SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1").bind(&message_id).fetch_one(&mut pg).await?;
                    if status=="published" {return Ok::<(),anyhow::Error>(());}
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }) => observed??,
        }
        worker_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), worker).await??;
        ensure!(
            self.call(Method::GET, &format!("/{}", expiry), None)
                .await?
                .1["commandStatus"]
                == "timed_out"
        );
        use rss_runtime::ManagedResource;
        rss_mdm_execution_service::Resource(restarted)
            .shutdown()
            .await?;
        pg.close().await?;
        Ok(())
    }
}
