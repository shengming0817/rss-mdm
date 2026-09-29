//! Real PG failure/role/concurrency tests, called by the native Windows T2 scenario.
use crate::windows::test_support::*;
use crate::{Database, Error, device::test_support::options};
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
        "mdm_access.operations",
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
    sqlx::query("INSERT INTO mdm_access.management_messages SELECT tenant_id,registration,session_id,1,repeat('f',64),decode('00','hex') FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id::int BETWEEN 1000 AND $3")
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
    let tenant = TENANT;
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
    let mut held_head = pg.begin().await?;
    let _: i32 =
        sqlx::query_scalar("SELECT 1 FROM rss_audit.heads WHERE tenant_id=$1::uuid FOR UPDATE")
            .bind(tenant)
            .fetch_one(&mut *held_head)
            .await?;
    ensure!(
        tokio::time::timeout(
            Duration::from_millis(500),
            crate::windows::retention::prune_management(store, &audit_store, tenant)
        )
        .await??
            == 0,
        "idle retention must not wait on the audit head"
    );
    held_head.rollback().await?;
    seed(&mut pg, tenant, registration, 1256).await?;
    ensure!(
        crate::windows::retention::prune_management(
            store,
            &audit_store,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        )
        .await?
            == 0
    );
    ensure!(messages(&mut pg, tenant).await? == 257);
    ensure!(queries(&mut pg, tenant).await? == 257);
    // A failure after deleting child rows rolls back both tables.
    pg.execute("CREATE FUNCTION mdm_access.reject_session_gc() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER reject_session_gc BEFORE DELETE ON mdm_access.management_sessions FOR EACH ROW EXECUTE FUNCTION mdm_access.reject_session_gc()").await?;
    ensure!(
        crate::windows::retention::prune_management(store, &audit_store, tenant)
            .await
            .is_err()
    );
    ensure!(messages(&mut pg, tenant).await? == 257);
    ensure!(queries(&mut pg, tenant).await? == 257);
    pg.execute("DROP TRIGGER reject_session_gc ON mdm_access.management_sessions; DROP FUNCTION mdm_access.reject_session_gc()").await?;
    let (a, b) = tokio::join!(
        crate::windows::retention::prune_management(store, &audit_store, tenant),
        crate::windows::retention::prune_management(store, &audit_store, tenant)
    );
    let (a, b) = (a?, b?);
    ensure!(a <= 32 && b <= 32 && a + b == 64);
    let mut pruned = a + b;
    loop {
        let count =
            crate::windows::retention::prune_management(store, &audit_store, tenant).await?;
        ensure!(count <= 32);
        pruned += count;
        if count == 0 {
            break;
        }
    }
    ensure!(pruned == 257);
    ensure!(
        crate::windows::retention::prune_management(store, &audit_store, tenant).await? == 0
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
    seed(&mut pg, tenant, registration, 1000).await?;
    // The production ManagedTask performs cleanup and drains within its lifecycle owner.
    let mut scope = rss_runtime::LifecycleScope::<(), Error, std::io::Error>::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(3))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let owner = restarted.clone();
    let scope_tenant = tenant.to_owned();
    let outcome = scope
        .drive(
            |startup| {
                Box::pin(async move {
                    let mut launch = startup.commit();
                    launch.stage_task_with_token(
                        crate::windows::retention::registration(
                            owner.clone(),
                            owner
                                .audit_store(&crate::config::AuditConfig::Plain)
                                .await
                                .unwrap(),
                            scope_tenant,
                        )
                        .critical(),
                    );
                    launch.finish();
                    std::future::pending().await
                })
            },
            async {
                tokio::time::sleep(Duration::from_millis(1200)).await;
                Ok(())
            },
        )
        .await?;
    ensure!(outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean()));
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
