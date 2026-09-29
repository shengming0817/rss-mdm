use super::*;
use anyhow::{Result, ensure};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

#[tokio::test(start_paused = true)]
async fn idle_wait_preserves_early_hints_and_recovers_lost_notifications() {
    use futures::FutureExt;
    let signals = Signals::default();
    let stop = CancellationToken::new();
    let notify = signals.get(Work::Inventory);
    // A commit between the work scan and registering the waiter retains one permit.
    signals.received("inventory");
    assert!(wait(notify, &stop, None).now_or_never().is_some());
    let idle = wait(notify, &stop, None);
    tokio::pin!(idle);
    assert!(idle.as_mut().now_or_never().is_none());
    tokio::time::advance(RECOVERY - Duration::from_millis(1)).await;
    assert!(idle.as_mut().now_or_never().is_none());
    tokio::time::advance(Duration::from_millis(1)).await;
    idle.await;
    let earlier = wait(notify, &stop, Some(Duration::from_millis(50)));
    tokio::pin!(earlier);
    assert!(earlier.as_mut().now_or_never().is_none());
    tokio::time::advance(Duration::from_millis(50)).await;
    earlier.await;
    stop.cancel();
    assert!(wait(notify, &stop, None).now_or_never().is_some());
}

async fn start(listener: &Listener) -> Result<rss_runtime::ShutdownStack> {
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(10))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(listener.clone()));
    let mut launch = startup.commit();
    launch.stage_task_with_token(listener.clone().registration().critical());
    launch.finish();
    // This signal is emitted only after LISTEN has completed.
    for work in Work::ALL {
        tokio::time::timeout(RECOVERY, listener.signals.get(work).notified()).await?;
    }
    Ok(owner)
}
async fn committed_count(connection: &mut PgConnection, tenant: &str) -> Result<i64> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant)
        .execute(&mut *connection)
        .await?;
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM mdm_access.devices WHERE tenant_id=$1::uuid")
            .bind(tenant)
            .fetch_one(connection)
            .await?,
    )
}
async fn stage(connection: &mut PgConnection, tenant: &str) -> Result<()> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)")
        .bind(tenant)
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *connection)
        .await?;
    notify(connection, Work::Inventory).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=worker.wake: PostgreSQL commit, LISTEN race, reconnect and two instances"]
async fn committed_hints_reconnect_and_restart_preserve_durable_work() -> Result<()> {
    use crate::device::test_support::options;
    let tenant = Uuid::new_v4().to_string();
    let mut writer = PgConnection::connect_with(&options("mdm_access")?).await?;
    let mut observer = PgConnection::connect_with(&options("mdm_access")?).await?;
    // Work committed before registration is discovered by the post-LISTEN initial scan.
    let mut before = writer.begin().await?;
    stage(&mut before, &tenant).await?;
    before.commit().await?;
    let name = format!("mdm-wake-test-{}", Uuid::new_v4());
    let listener = Listener::new(options("mdm_access")?.application_name(&name));
    let other = Listener::new(options("mdm_access")?);
    let owner = start(&listener).await?;
    let peer = start(&other).await?;
    ensure!(committed_count(&mut observer, &tenant).await? == 1);
    let hint = listener.signals.get(Work::Inventory);
    let peer_hint = other.signals.get(Work::Inventory);
    let asset_hint = listener.signals.get(Work::AutomationInput);
    let mut tx = writer.begin().await?;
    stage(&mut tx, &tenant).await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(50), hint.notified())
            .await
            .is_err()
    );
    ensure!(committed_count(&mut observer, &tenant).await? == 1);
    ensure!(
        tokio::time::timeout(Duration::from_millis(50), asset_hint.notified())
            .await
            .is_err()
    );
    tx.rollback().await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(50), hint.notified())
            .await
            .is_err()
    );
    let mut tx = writer.begin().await?;
    stage(&mut tx, &tenant).await?;
    tx.commit().await?;
    tokio::time::timeout(RECOVERY, hint.notified()).await?;
    tokio::time::timeout(RECOVERY, peer_hint.notified()).await?;
    tokio::time::timeout(RECOVERY, asset_hint.notified()).await?;
    ensure!(committed_count(&mut observer, &tenant).await? == 2);
    // Terminate only this test's listener. Its completed reconnect causes another scan.
    let mut admin = PgConnection::connect_with(&options("postgres")?).await?;
    let pid: i32 = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND datname=current_database()",
    )
    .bind(&name)
    .fetch_one(&mut admin)
    .await?;
    let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(&mut admin)
        .await?;
    ensure!(killed);
    tokio::time::timeout(Duration::from_secs(10), hint.notified()).await?;
    let mut tx = writer.begin().await?;
    stage(&mut tx, &tenant).await?;
    tx.commit().await?;
    tokio::time::timeout(RECOVERY, hint.notified()).await?;
    ensure!(committed_count(&mut observer, &tenant).await? == 3);
    ensure!(owner.shutdown().join().await?.is_clean());
    ensure!(peer.shutdown().join().await?.is_clean());
    // Lost hints during process downtime cannot lose the committed marker.
    let mut tx = writer.begin().await?;
    stage(&mut tx, &tenant).await?;
    tx.commit().await?;
    let restarted = Listener::new(options("mdm_access")?);
    let owner = start(&restarted).await?;
    ensure!(committed_count(&mut observer, &tenant).await? == 4);
    ensure!(owner.shutdown().join().await?.is_clean());
    Ok(())
}
