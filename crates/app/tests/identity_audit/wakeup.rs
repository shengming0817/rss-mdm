use super::*;

#[tokio::test(start_paused = true)]
async fn idle_is_bounded_by_durable_time_and_empty_claims_cannot_spin() -> Result<()> {
    let mut idle = Idle::default();
    ensure!(idle.delay(RECOVERY) == Duration::from_secs(30));
    ensure!(idle.rescan(true));
    for _ in 0..1000 {
        ensure!(!idle.rescan(true));
    }
    ensure!(idle.delay(RECOVERY) == RECOVERY);
    idle.nearest = Some(Deadline::from_timeout(
        &crate::lifecycle::RuntimeTimer,
        Duration::from_secs(2),
    )?);
    ensure!(idle.delay(RECOVERY) == Duration::from_secs(2));
    ensure!(idle.delay(BACKOFF) == BACKOFF);
    tokio::time::advance(Duration::from_millis(1500)).await;
    ensure!(idle.delay(BACKOFF) == Duration::from_millis(500));
    tokio::time::advance(Duration::from_millis(500)).await;
    // A formerly future candidate is now due; one rescan is already spent.
    ensure!(!idle.rescan(false));
    ensure!(idle.delay(RECOVERY) == RECOVERY);
    Ok(())
}

pub(super) async fn event_driven_delivery(
    config: &Config,
    identity: &crate::identity::Identity,
    observer: &PgPool,
    expected: i64,
) -> Result<()> {
    let name = format!("identity-wake-{}", uuid::Uuid::new_v4());
    let listener = crate::worker_wake::Listener::new(
        config.access_database.options()?.application_name(&name),
        identity.tenant,
    )
    .with_identity(
        identity.instance,
        [identity.tenant, identity.management_tenant],
    );
    let readiness = Arc::new(Readiness::default());
    let mut resources = Vec::new();
    let worker = Worker::open(
        config,
        readiness.clone(),
        listener.signals.audit.clone(),
        |r| resources.push(r),
    )
    .await?;
    let mut scope = LifecycleScope::<(), std::io::Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(40))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let listener_task = listener.clone().registration().critical();
    let worker_task = worker.clone().registration().critical();
    let listener_resource = rss_runtime::DynManagedResource::new_box(listener.clone());
    let check = async {
        wait_delivered(observer, &readiness, expected).await?;
        tokio::time::timeout(
            Duration::from_secs(5),
            listener
                .signals
                .get(crate::worker_wake::Work::Inventory)
                .notified(),
        )
        .await?;
        wait_idle(&worker).await?;
        login(identity).await?;
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_delivered(observer, &readiness, expected + 1),
        )
        .await??;
        wait_idle(&worker).await?;
        durable_retry(identity, observer, &readiness, expected + 1).await?;
        wait_idle(&worker).await?;
        // Lose the wake hint entirely: reconnect must discover durable work.
        manipulate(observer, "UPDATE rss_transactional_messaging.outbox SET status='pending',retry_after=clock_timestamp() WHERE seq=(SELECT max(seq) FROM rss_transactional_messaging.outbox WHERE tenant_id=current_setting('rss.tenant_id')::uuid AND domain='identity.security')").await?;
        // Reconnection of the same listener must scan and retain every subscription.
        let pid: i32 = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND datname=current_database()")
            .bind(&name).fetch_one(observer).await?;
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(observer)
            .await?;
        tokio::time::timeout(
            Duration::from_secs(10),
            listener
                .signals
                .get(crate::worker_wake::Work::Inventory)
                .notified(),
        )
        .await?;
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_delivered(observer, &readiness, expected + 1),
        )
        .await??;
        wait_idle(&worker).await?;
        login(identity).await?;
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_delivered(observer, &readiness, expected + 2),
        )
        .await??;
        Ok::<(), anyhow::Error>(())
    };
    let signal = async {
        tokio::time::timeout(Duration::from_secs(20), check)
            .await
            .map_err(std::io::Error::other)?
            .map_err(std::io::Error::other)
    };
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    for resource in resources {
                        startup.stage_resource(resource);
                    }
                    startup.stage_resource(listener_resource);
                    let mut launch = startup.commit();
                    launch.stage_task_with_token(listener_task);
                    launch.stage_deferred_task_with_token(worker_task);
                    launch.finish();
                    std::future::pending().await
                })
            },
            signal,
        )
        .await?;
    if let ScopeExit::StopRequested(Err(error)) = outcome.exit() {
        return Err(anyhow::anyhow!("notification delivery: {error}"));
    }
    ensure!(outcome.shutdown().is_ok());
    ensure!(!readiness.health().is_ready());
    Ok(())
}

async fn durable_retry(
    identity: &crate::identity::Identity,
    observer: &PgPool,
    readiness: &Readiness,
    expected: i64,
) -> Result<()> {
    manipulate(observer, "UPDATE rss_transactional_messaging.outbox SET status='pending',retry_after=clock_timestamp()+interval '2 seconds' WHERE seq=(SELECT max(seq) FROM rss_transactional_messaging.outbox WHERE tenant_id=current_setting('rss.tenant_id')::uuid AND domain='identity.security')").await?;
    sqlx::query("SELECT pg_notify($1,'')")
        .bind(rss_identity_postgres::audit::notification_channel(
            identity.instance,
            identity.tenant,
        ))
        .execute(observer)
        .await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE status='pending'",
    )
    .fetch_one(observer)
    .await?;
    ensure!(pending == 1, "future retry was claimed before eligibility");
    // No second notification: the persistent deadline wakes well before 30-second recovery.
    tokio::time::timeout(
        Duration::from_secs(5),
        wait_delivered(observer, readiness, expected),
    )
    .await??;
    Ok(())
}

async fn wait_idle(worker: &Worker) -> Result<()> {
    let before = worker.idle_count.load(Ordering::Acquire);
    worker.wake.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        while worker.idle_count.load(Ordering::Acquire) == before {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}
