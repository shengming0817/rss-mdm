//! Real PG failure/role/concurrency tests, called by the native Windows T2 scenario.
use crate::windows::test_support::*;
use crate::{Database, device::test_support::options};
use anyhow::ensure;
use axum::http::StatusCode;
use rss_mdm_windows_mdm::{CodecLimits, syncml};
use sqlx::{Connection, Executor, PgConnection};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

async fn history(pg: &mut PgConnection, tenant: &str) -> anyhow::Result<Vec<String>> {
    let mut hashes = Vec::new();
    for table in [
        "mdm_access.grants",
        "mdm_access.requests",
        "mdm_access.registration_operations",
        "mdm_windows.operations",
        "mdm_access.devices",
        "mdm_access.registrations",
        "mdm_access.credentials",
        "mdm_access.report_sources",
        "mdm_access.enrollment_intents",
        "mdm_access.enrollment_certificates",
        "rss_audit.records",
        "mdm_audit.receipts",
        "rss_ledger.entries",
    ] {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT md5(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'')) FROM ",
        );
        query
            .push(table)
            .push(" t WHERE tenant_id=")
            .push_bind(tenant)
            .push("::uuid");
        hashes.push(query.build_query_scalar().fetch_one(&mut *pg).await?);
    }
    Ok(hashes)
}
async fn seed(
    pg: &mut PgConnection,
    tenant: &str,
    registration: Uuid,
    last: i32,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO mdm_access.management_sessions SELECT s.tenant_id,s.registration,n::text,s.generation,s.credential,'complete',1,s.client_authenticated,s.correlation,s.nonce,clock_timestamp()-interval '1 second',NULL::uuid FROM (SELECT * FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND expires_at>clock_timestamp() ORDER BY session_id LIMIT 1) s CROSS JOIN generate_series(1000,$3) n")
        .bind(tenant).bind(registration.to_string()).bind(last).execute(&mut *pg).await?;
    sqlx::query("INSERT INTO mdm_access.management_messages SELECT tenant_id,registration,session_id,1,repeat('f',64),decode(repeat('00',68),'hex') FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id::int BETWEEN 1000 AND $3")
        .bind(tenant).bind(registration.to_string()).bind(last).execute(&mut *pg).await?;
    sqlx::query("INSERT INTO mdm_commands.capability_queries(tenant_id,registration,generation,session,request,version_command,edition_command) SELECT tenant_id,registration,generation,session_id::bigint,decode('00','hex'),1,2 FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id::int BETWEEN 1000 AND $3")
        .bind(tenant).bind(registration.to_string()).bind(last).execute(&mut *pg).await?;
    Ok(())
}
async fn queries(pg: &mut PgConnection, tenant: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM mdm_commands.capability_queries WHERE tenant_id=$1::uuid AND session>=1000").bind(tenant).fetch_one(pg).await?)
}
async fn messages(pg: &mut PgConnection, tenant: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND session_id::int>=1000").bind(tenant).fetch_one(pg).await?)
}
#[tokio::test]
#[ignore = "make t2 MODULE=windows.retention"]
async fn bounded_pruning_preserves_durable_history() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let store = &host.store;
    let tenant = case_tenant();
    let registration = peer.intent.registration;
    let response = peer
        .mutual
        .post(&peer.url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(syncml::encode(&peer.message, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let response = peer
        .mutual
        .post(&peer.url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(syncml::encode(&peer.ack, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let before = history(&mut pg, tenant).await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid",
    )
    .bind(tenant)
    .fetch_one(&mut pg)
    .await?;
    // The role itself cannot delete a live session or its exact response.
    let mut tx = store.begin(tenant).await?;
    ensure!(
        sqlx::query("DELETE FROM mdm_access.management_messages")
            .execute(&mut *tx)
            .await?
            .rows_affected()
            == 0
    );
    ensure!(
        sqlx::query("DELETE FROM mdm_access.management_sessions")
            .execute(&mut *tx)
            .await?
            .rows_affected()
            == 0
    );
    tx.rollback().await?;
    let audit_store = store
        .audit_store(&crate::config::AuditConfig::Plain)
        .await?;
    // Only the deadline query uses ceil(numeric); other empty work succeeds.
    pg.execute("REVOKE EXECUTE ON FUNCTION pg_catalog.ceil(numeric) FROM PUBLIC")
        .await?;
    let failed_deadline =
        rss_mdm_windows_channel::retention::sweep(&store.windows_store(), &audit_store, tenant)
            .await;
    pg.execute("GRANT EXECUTE ON FUNCTION pg_catalog.ceil(numeric) TO PUBLIC")
        .await?;
    ensure!(
        failed_deadline.is_err(),
        "deadline query failure became healthy idle"
    );
    ensure!(
        rss_mdm_windows_channel::retention::sweep(&store.windows_store(), &audit_store, tenant)
            .await?
            .0
            == 0
    );
    let mut held_head = pg.begin().await?;
    let _: i32 =
        sqlx::query_scalar("SELECT 1 FROM rss_audit.heads WHERE tenant_id=$1::uuid FOR UPDATE")
            .bind(tenant)
            .fetch_one(&mut *held_head)
            .await?;
    ensure!(
        tokio::time::timeout(
            Duration::from_millis(500),
            rss_mdm_windows_channel::retention::prune_management(
                &store.windows_store(),
                &audit_store,
                tenant
            )
        )
        .await??
            == 0,
        "idle retention must not wait on the audit head"
    );
    held_head.rollback().await?;
    seed(&mut pg, tenant, registration, 1256).await?;
    ensure!(
        rss_mdm_windows_channel::retention::prune_management(
            &store.windows_store(),
            &audit_store,
            crate::test_support::case::peer()
        )
        .await?
            == 0
    );
    ensure!(messages(&mut pg, tenant).await? == 257);
    ensure!(queries(&mut pg, tenant).await? == 257);
    // A failure after deleting child rows rolls back both tables.
    pg.execute("CREATE FUNCTION mdm_access.reject_session_gc() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER reject_session_gc BEFORE DELETE ON mdm_access.management_sessions FOR EACH ROW EXECUTE FUNCTION mdm_access.reject_session_gc()").await?;
    ensure!(
        rss_mdm_windows_channel::retention::prune_management(
            &store.windows_store(),
            &audit_store,
            tenant
        )
        .await
        .is_err()
    );
    ensure!(messages(&mut pg, tenant).await? == 257);
    ensure!(queries(&mut pg, tenant).await? == 257);
    pg.execute("DROP TRIGGER reject_session_gc ON mdm_access.management_sessions; DROP FUNCTION mdm_access.reject_session_gc()").await?;
    let channel_store = store.windows_store();
    let (a, b) = tokio::join!(
        rss_mdm_windows_channel::retention::prune_management(&channel_store, &audit_store, tenant),
        rss_mdm_windows_channel::retention::prune_management(&channel_store, &audit_store, tenant)
    );
    let (a, b) = (a?, b?);
    ensure!(a <= 32 && b <= 32 && a + b == 64);
    let mut pruned = a + b;
    loop {
        let count = rss_mdm_windows_channel::retention::prune_management(
            &store.windows_store(),
            &audit_store,
            tenant,
        )
        .await?;
        ensure!(count <= 32);
        pruned += count;
        if count == 0 {
            break;
        }
    }
    ensure!(pruned == 257);
    ensure!(
        rss_mdm_windows_channel::retention::prune_management(
            &store.windows_store(),
            &audit_store,
            tenant
        )
        .await?
            == 0
            && messages(&mut pg, tenant).await? == 0
    );
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid"
        )
        .bind(tenant)
        .fetch_one(&mut pg)
        .await?
            == live
    );
    // Policy weakening is rejected at startup, even though tenant isolation remains installed.
    pg.execute("ALTER POLICY expired_only ON mdm_access.management_sessions USING(true)")
        .await?;
    ensure!(Database::connect(options("mdm_access")?).await.is_err());
    pg.execute("ALTER POLICY expired_only ON mdm_access.management_sessions USING(expires_at<clock_timestamp())").await?;
    let restarted = Arc::new(Database::connect(options("mdm_access")?).await?);
    // Start with future work: startup cannot prune it, and the five-second fallback
    // is too late for this assertion. The production task must use nearest expiry.
    schedule(&mut pg, tenant, registration, "1000", 1000, false).await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(3))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let startup = owner.startup()?;
    let mut launch = startup.commit();
    launch.stage_task_with_token(
        rss_mdm_windows_channel::retention::registration(
            restarted.windows_store(),
            restarted
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
            tenant.to_owned(),
            host.notifications
                .signals
                .handle(crate::worker_wake::Work::Windows),
        )
        .critical(),
    );
    launch.finish();
    tokio::time::sleep(Duration::from_millis(200)).await;
    ensure!(
        scheduled_count(&mut pg, tenant, "1000").await? == 1,
        "future session was pruned early"
    );
    await_pruned(&mut pg, tenant, "1000", Duration::from_secs(3)).await?;
    // A later deadline is already idle; a new earlier committed deadline must
    // interrupt it through the real LISTEN connection, then sleep until due.
    schedule(&mut pg, tenant, registration, "1001", 20000, true).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    schedule(&mut pg, tenant, registration, "1002", 700, true).await?;
    await_pruned(&mut pg, tenant, "1002", Duration::from_secs(3)).await?;
    ensure!(scheduled_count(&mut pg, tenant, "1001").await? == 1);
    // A committed expiry without any hint still recovers from durable state.
    tokio::time::sleep(Duration::from_millis(300)).await;
    schedule(&mut pg, tenant, registration, "1003", 200, false).await?;
    await_pruned(&mut pg, tenant, "1003", Duration::from_secs(7)).await?;
    ensure!(owner.shutdown().join().await?.is_clean());
    ensure!(messages(&mut pg, tenant).await? == 0);
    ensure!(queries(&mut pg, tenant).await? == 0);
    ensure!(
        history(&mut pg, tenant).await? == before,
        "retention changed authoritative facts"
    );
    restarted.close().await;
    pg.close().await?;
    host.close().await?;
    Ok(())
}

async fn schedule(
    pg: &mut PgConnection,
    tenant: &str,
    registration: Uuid,
    session: &str,
    millis: i64,
    hint: bool,
) -> anyhow::Result<()> {
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_access.management_sessions SELECT s.tenant_id,s.registration,$3,s.generation,s.credential,'complete',1,s.client_authenticated,s.correlation,s.nonce,clock_timestamp()+$4*interval '1 millisecond',NULL::uuid FROM (SELECT * FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id::int<1000 ORDER BY session_id LIMIT 1) s")
        .bind(tenant).bind(registration.to_string()).bind(session).bind(millis).execute(&mut *tx).await?;
    if hint {
        crate::worker_wake::notify(&mut tx, crate::worker_wake::Work::Windows).await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn scheduled_count(
    pg: &mut PgConnection,
    tenant: &str,
    session: &str,
) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND session_id=$2").bind(tenant).bind(session).fetch_one(pg).await?)
}
async fn await_pruned(
    pg: &mut PgConnection,
    tenant: &str,
    session: &str,
    limit: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(limit, async {
        while scheduled_count(pg, tenant, session).await? != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
