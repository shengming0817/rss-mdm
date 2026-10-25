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
    host.resources.finish(async { Ok(()) }).await?;
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
        ensure!(
            self.call(
                Method::POST,
                "",
                Some(
                    json!({"operationId":expiry,"action":{"kind":"restart"},"deadline":expires_at})
                )
            )
            .await?
            .0 == StatusCode::ACCEPTED
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let audit = self.audit_store.clone();
        let sessions = self.sessions.clone();
        let restart_clock = clock.clone();
        let (resources, (restarted, restarted_runtime)) =
            crate::test_support::runtime::Resources::build(move |resources| {
                Box::pin(async move {
                    let (restarted, _, runtime) = crate::test_support::command::command_service(
                        audit,
                        sessions,
                        rss_device_command_postgres::CommandClock::Controlled(restart_clock),
                    )
                    .await?;
                    resources.resource(rss_mdm_execution_service::Resource(restarted.clone()));
                    Ok((restarted, runtime))
                })
            })
            .await?;
        resources.finish(async {
        eprintln!("command T2: restarted runtime admitted");
        let persisted: (String, String) = sqlx::query_as(
            "SELECT c.status,o.status FROM rss_device_command.commands c JOIN rss_transactional_messaging.outbox o ON o.tenant_id=c.tenant_id AND o.message_id=c.outbox_message_id WHERE c.tenant_id=$1::uuid AND c.command_id=$2",
        ).bind(case_tenant()).bind(expiry.to_string()).fetch_one(&mut pg).await?;
        ensure!(persisted == ("queued".into(), "pending".into()));
        let sibling=Uuid::new_v4();
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":sibling,"action":{"kind":"restart"},"deadline":expires_at+100}))).await?.0==StatusCode::ACCEPTED);
        let first=self.browser.call(&self.router,Method::GET,"/api/v1/operations?limit=1&fields=id,kind",None).await?;
        ensure!(first.0==StatusCode::OK,"pre-recovery directory: {first:?}");
        let token=first.1["nextCursor"].as_str().ok_or_else(||anyhow::anyhow!("recovery continuation"))?;
        let continuation=format!("/api/v1/operations?limit=1&fields=id,kind&cursor={token}");
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
        let scope = recovery_scope(self.tenant);
        let mut fence = pg.begin().await?;
        crate::Database::configure_transaction(&mut fence,case_tenant()).await?;
        rss_mdm_inventory_postgres::lock_watermark_in(&mut fence,self.tenant).await?;
        let release = async {
            tokio::time::timeout(Duration::from_secs(1),async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))")
                        .fetch_one(&mut *fence).await?;
                    if waiting { break; }
                    sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *fence).await?;
                    tokio::task::yield_now().await;
                }
                // Exercise the real producer wake while the worker is waiting for its
                // earlier business fence. The old protect-before-watermark path times out.
                sqlx::query("SET LOCAL lock_timeout='250ms'").execute(&mut *fence).await?;
                let target = rss_mdm_execution_service::target(self.tenant,case_device());
                sqlx::query("SELECT rss_reconcile.wake($1::uuid,$2,$3)")
                    .bind(case_tenant()).bind(target.scope().reconciler()).bind(target.entity())
                    .execute(&mut *fence).await?;
                Ok::<_,anyhow::Error>(())
            }).await??;
            fence.commit().await?;
            Ok::<_,anyhow::Error>(())
        };
        let notify = tokio::sync::Notify::new();
        let (report,released) = tokio::join!(
            restarted.run_recovery(&scope,policy,&control,&notify), release
        );
        released?;
        let report = report?;
        ensure!(
            report.execution_failed == 0 && report.suspended == 0,
            "recovery did not complete {:?}",
            report
        );
        ensure!(self.browser.call(&self.router,Method::GET,&continuation,None).await?.0==StatusCode::CONFLICT,"command recovery did not invalidate the original page");
        let read = self
            .call(Method::GET, &format!("/{}", expiry), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "timed_out" && read.1["observation"]["effect"] == "waiting",
            "expiry or unknown effect lost {:?}",
            read
        );
        // Bind the wake to the restarted runtime before corrupting the catalog.
        // Make an actual operation due so the worker must reject its claim.
        let reconcile = rss_reconcile_postgres::PgMessagingStore::new(
            restarted_runtime.clone(), self.tenant, deadline(),
        ).await?;
        let target = rss_mdm_execution_service::target(self.tenant, case_device());
        restarted_runtime
            .local_tx_with_context(
                self.tenant,
                deadline(),
                (reconcile, target),
                |(reconcile, target), tx| {
                    Box::pin(async move {
                        reconcile.wake_in(tx, target, (), |_, _| {
                            Box::pin(async { Ok(()) })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        sqlx::raw_sql("ALTER FUNCTION rss_reconcile.claim_due(uuid,text,integer,bigint) RENAME TO claim_due_unavailable")
            .execute(&mut pg)
            .await?;
        let fatal_timer = recovery::Timer::new();
        let fatal_control =
            rss_reconcile::Control::new(&fatal_timer, Duration::from_secs(2), &cancel);
        let fatal = restarted
            .run_recovery(&scope, policy, &fatal_control, &tokio::sync::Notify::new())
            .await;
        sqlx::raw_sql("ALTER FUNCTION rss_reconcile.claim_due_unavailable(uuid,text,integer,bigint) RENAME TO claim_due")
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
        let execution_signals = signals.execution();
        let mut worker = Box::pin(
            restarted
                .run_worker(&worker_cancel, &execution_signals),
        );
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
        pg.close().await?;
        Ok(())
        }).await
    }
}
