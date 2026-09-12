//! Real PG failure/role/concurrency tests, called by the native Windows T2 scenario.
use crate::{AccessStore, Error, device::tests::options};
use anyhow::ensure;
use sqlx::{Connection, Executor, PgConnection};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

async fn history(pg: &mut PgConnection, tenant: &str) -> anyhow::Result<Vec<String>> {
    let mut hashes = Vec::new();
    for table in [
        "grants",
        "requests",
        "operations",
        "audit",
        "devices",
        "registrations",
        "credentials",
        "report_sources",
        "enrollment_intents",
        "enrollment_certificates",
    ] {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT md5(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'')) FROM mdm_access.",
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
    Ok(())
}
async fn messages(pg: &mut PgConnection, tenant: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND session_id::int>=1000").bind(tenant).fetch_one(pg).await?)
}
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential real-PG failure and lifecycle acceptance matrix"
)]
pub(super) async fn verify(
    store: &Arc<AccessStore>,
    tenant: &str,
    registration: Uuid,
) -> anyhow::Result<()> {
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
    seed(&mut pg, tenant, registration, 1256).await?;
    ensure!(
        store
            .prune_management("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
            .await?
            == 0
    );
    ensure!(messages(&mut pg, tenant).await? == 257);
    // A failure after deleting child rows rolls back both tables.
    pg.execute("CREATE FUNCTION mdm_access.reject_session_gc() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER reject_session_gc BEFORE DELETE ON mdm_access.management_sessions FOR EACH ROW EXECUTE FUNCTION mdm_access.reject_session_gc()").await?;
    ensure!(store.prune_management(tenant).await.is_err());
    ensure!(messages(&mut pg, tenant).await? == 257);
    pg.execute("DROP TRIGGER reject_session_gc ON mdm_access.management_sessions; DROP FUNCTION mdm_access.reject_session_gc()").await?;
    let (a, b) = tokio::join!(
        store.prune_management(tenant),
        store.prune_management(tenant)
    );
    let (a, b) = (a?, b?);
    ensure!(a <= 128 && b <= 128 && a + b == 256);
    ensure!(store.prune_management(tenant).await? == 1);
    ensure!(store.prune_management(tenant).await? == 0 && messages(&mut pg, tenant).await? == 0);
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
    ensure!(AccessStore::connect(options("mdm_access")?).await.is_err());
    pg.execute("ALTER POLICY expired_only ON mdm_access.management_sessions USING(expires_at<clock_timestamp())").await?;
    let restarted = Arc::new(AccessStore::connect(options("mdm_access")?).await?);
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
                        super::retention::registration(owner, scope_tenant).critical(),
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
    ensure!(
        history(&mut pg, tenant).await? == before,
        "retention changed authoritative facts"
    );
    restarted.close().await;
    pg.close().await?;
    Ok(())
}
