//! A deferred trigger holds the actual COMMIT. The one-connection relay keeps TLS
//! end to end and drops only the next server response after the database reaches that gate.
use super::*;
use crate::authority_t2_support::wait_for_blocked_attempt;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

pub(super) async fn exercise(
    h: &Harness,
    page: &Page,
    store: &rss_projection_postgres::PgStore,
) -> Result<()> {
    let after = reset(h).await?;
    let cancel = CancellationToken::new();
    let control = page.control(&cancel);
    let worker = page
        .worker(h, store, GenerationStart::beginning(), &control)
        .await?;
    let id = page.reports[2].id().as_str();
    let tenant = h.c.tenant.to_string();

    // The second applicable event still has a genuine RSS record. Its referenced
    // product result must pass Inventory's integrity check in the effect transaction.
    let saved: Vec<u8> = sqlx::query_scalar(
        "SELECT document FROM mdm.collection_results WHERE tenant_id=$1::uuid AND run=$2",
    )
    .bind(&tenant)
    .bind(id)
    .fetch_one(&h.c.operator)
    .await?;
    sqlx::query("UPDATE mdm.collection_results SET document=decode('00','hex') WHERE tenant_id=$1::uuid AND run=$2").bind(&tenant).bind(id).execute(&h.c.operator).await?;
    let rejected = rss_projection::run_batched(&*page.source, &worker, &control, limit()?).await;
    assert!(rejected.into_result().is_err());
    assert_eq!(progress(&h.c).await?, (None, 0, 0));
    assert!(business(&h.c, after).await?.0.is_empty());
    sqlx::query(
        "UPDATE mdm.collection_results SET document=$3 WHERE tenant_id=$1::uuid AND run=$2",
    )
    .bind(&tenant)
    .bind(id)
    .bind(saved)
    .execute(&h.c.operator)
    .await?;

    let db = h.c.inputs.database(&h.c.profile, "mdm_runtime");
    let gate = Uuid::new_v4();
    let lock = i64::from_be_bytes(gate.as_bytes()[..8].try_into()?);
    let name = format!("gate_{}", gate.simple());
    let function = format!("public.{name}");
    let id = Uuid::parse_str(id)?;
    let mut ddl = h.c.operator.begin().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({lock}::bigint); RETURN NEW; END $$;
        CREATE TRIGGER {name} BEFORE INSERT OR UPDATE ON mdm.inventory FOR EACH ROW WHEN (NEW.tenant_id='{tenant}' AND NEW.batch_id='{id}') EXECUTE FUNCTION {function}()"))).execute(&mut *ddl).await?;
    ddl.commit().await?;
    let mut hold = h.c.operator.begin().await?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid() FROM pg_advisory_xact_lock($1)")
        .bind(lock)
        .fetch_one(&mut *hold)
        .await?;
    let stop = async {
        wait_for_blocked_attempt(&h.c.operator, pid, "mdm.inventory").await?;
        cancel.cancel();
        Ok::<_, anyhow::Error>(())
    };
    let (report, stopped) = tokio::join!(
        rss_projection::run_batched(&*page.source, &worker, &control, limit()?),
        stop
    );
    stopped?;
    hold.rollback().await?;
    assert_eq!(
        report.into_result().unwrap_err().kind(),
        rss_projection::ErrorKind::Cancelled
    );
    assert_eq!(progress(&h.c).await?, (None, 0, 0));
    assert!(business(&h.c, after).await?.0.is_empty());

    let mut ddl = h.c.operator.begin().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP TRIGGER {name} ON mdm.inventory;
        CREATE CONSTRAINT TRIGGER {name} AFTER INSERT OR UPDATE ON mdm.inventory DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.tenant_id='{tenant}' AND NEW.batch_id='{id}') EXECUTE FUNCTION {function}()"))).execute(&mut *ddl).await?;
    ddl.commit().await?;
    let mut hold = h.c.operator.begin().await?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid() FROM pg_advisory_xact_lock($1)")
        .bind(lock)
        .fetch_one(&mut *hold)
        .await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let armed = CancellationToken::new();
    let lost = armed.clone();
    let relay = tokio::spawn(async move {
        let (client, _) = listener.accept().await?;
        let server = TcpStream::connect((db.host.as_str(), db.port)).await?;
        let (mut from_client, mut to_client) = client.into_split();
        let (mut from_server, mut to_server) = server.into_split();
        let forward = tokio::io::copy(&mut from_client, &mut to_server);
        let responses = async {
            let mut bytes = [0; 8192];
            loop {
                let n = from_server.read(&mut bytes).await?;
                anyhow::ensure!(n > 0, "upstream closed before settlement");
                if lost.is_cancelled() {
                    return Ok::<_, anyhow::Error>(());
                }
                to_client.write_all(&bytes[..n]).await?;
            }
        };
        tokio::select! { r=forward => anyhow::bail!("client closed before settlement: {r:?}"), r=responses => r }
    });
    let proxy = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(h.c.inputs.options(&h.c.profile, "mdm_runtime")?.port(port))
        .await?;
    let token = CancellationToken::new();
    let control = page.control(&token);
    let uncertain_store = rss_projection_postgres::PgStore::new(proxy.clone(), &control).await?;
    let uncertain = page
        .worker(h, &uncertain_store, GenerationStart::beginning(), &control)
        .await?;
    let lose = async {
        wait_for_blocked_attempt(&h.c.operator, pid, "COMMIT").await?;
        armed.cancel();
        hold.rollback().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (report, lost) = tokio::join!(
        rss_projection::run_batched(&*page.source, &uncertain, &control, limit()?),
        lose
    );
    lost?;
    relay.await??;
    assert_eq!(report.applied, 0);
    assert_eq!(
        report.into_result().unwrap_err().kind(),
        rss_projection::ErrorKind::CommitUnknown
    );
    assert_eq!(progress(&h.c).await?, (Some(3), 3, 1));
    let snapshot = business(&h.c, after).await?;
    assert_eq!((snapshot.0.len(), snapshot.1), (3, 1));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {name} ON mdm.inventory; DROP FUNCTION {function}()"
    )))
    .execute(&h.c.operator)
    .await?;
    let resumed = page
        .worker(h, store, GenerationStart::beginning(), &control)
        .await?;
    assert_eq!(
        rss_projection::run_batched(&*page.source, &resumed, &control, limit()?)
            .await
            .into_result()?
            .applied,
        0
    );
    assert_eq!(business(&h.c, after).await?, snapshot);
    proxy.close().await;
    Ok(())
}
