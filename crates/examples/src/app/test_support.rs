use crate::{app::App, fixture::FixtureAuthority, storage};
use anyhow::{Result, ensure};
use rss_mdm_inventory as model;
use rss_mdm_inventory_postgres::{Inventory, definition};
use rss_observation::{
    Batch, Body, Change, Id, ObservationStore, ReceiveOutcome, Scope, VerifiedBatch,
};
use rss_projection::{BatchLimit, Control, Execution, RunLimit, Source};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn scope(tenant: u8, device: &str) -> Scope {
    serde_json::from_value(serde_json::json!({"tenant":format!("00000000-0000-0000-0000-{tenant:012}"),"object":device,"registration":"reg-1","source":"fixture","dataset":"inventory","epoch":"epoch-1"})).unwrap()
}
#[allow(
    clippy::disallowed_methods,
    reason = "Real PG fixture timestamp must track server wall time"
)]
fn batch(id: &str, sequence: u64, body: Body) -> Batch {
    Batch::new(
        Id::new(id).unwrap(),
        sequence,
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
        model::coverage(),
        body,
    )
    .unwrap()
}
fn facts(value: &str) -> Vec<Change> {
    vec![
        Change::upsert(Id::new("device.model").unwrap(), value.as_bytes().to_vec()),
        Change::upsert(Id::new("device.os.version").unwrap(), b"1".to_vec()),
    ]
}
fn url(name: &str) -> Result<PgConnectOptions> {
    Ok(std::env::var(name)?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?))
}
async fn app(s: Scope) -> Result<App> {
    Box::pin(App::open(
        &storage::options()?,
        FixtureAuthority::new(s),
        system_clock(),
    ))
    .await
}
async fn inspect(a: &App, id: &str) -> Result<serde_json::Value> {
    a.inspect(&Id::new(id)?).await
}

/// Runs the real provider fault and lifecycle scenarios without exposing component handles.
pub async fn matrix(executable: &str) -> Result<()> {
    let a = app(scope(1, "d1")).await?;
    let cancel = CancellationToken::new();
    let first = batch("first", 0, Body::Snapshot(facts("Model-A")));
    assert!(matches!(
        a.ingest(first.clone()).await?,
        ReceiveOutcome::Accepted(_)
    ));
    assert!(
        inspect(&a, "first").await?["assets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(inspect(&a, "first").await?["projection"], "not_projected");
    assert_eq!(a.project(&cancel).await?["applied"], 1);
    let original = inspect(&a, "first").await?;
    assert_eq!(original["projection"], "projected");
    assert_eq!(original["assets"].as_array().unwrap().len(), 2);
    assert!(matches!(
        a.ingest(first.clone()).await?,
        ReceiveOutcome::Replay(_)
    ));
    assert!(
        a.ingest(batch("first", 0, Body::Snapshot(facts("Conflict"))))
            .await
            .is_err()
    );
    assert_eq!(a.project(&cancel).await?["applied"], 0);
    assert_eq!(inspect(&a, "first").await?, original);
    for (i, body) in [
        Body::Partial(facts("partial")),
        Body::Failed {
            code: Id::new("collection-failed")?,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("incomplete-{i}");
        a.ingest(batch(&id, i as u64 + 1, body)).await?;
        assert_eq!(a.project(&cancel).await?["applied"], 0);
        let view = inspect(&a, &id).await?;
        assert!(!view["receipt"].is_null());
        assert_eq!(view["projection"], "not_projected");
        assert_eq!(view["assets"], original["assets"]);
        assert_eq!(view["checkpoint"], original["checkpoint"]);
    }
    a.ingest(batch("full", 3, Body::Snapshot(facts("Model-B"))))
        .await?;
    a.project(&cancel).await?;
    a.ingest(batch(
        "delta",
        4,
        Body::Delta {
            baseline: Id::new("full")?,
            previous: 3,
            changes: vec![Change::delete(Id::new("device.os.version")?)],
        },
    ))
    .await?;
    a.project(&cancel).await?;
    assert_eq!(
        inspect(&a, "delta").await?["assets"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let other = app(scope(2, "d1")).await?;
    other
        .ingest(batch("first", 0, Body::Snapshot(facts("Tenant-B"))))
        .await?;
    other.project(&cancel).await?;
    let sibling = app(scope(1, "d2")).await?;
    sibling
        .ingest(batch("first", 0, Body::Snapshot(facts("Sibling"))))
        .await?;
    assert_eq!(
        inspect(&sibling, "first").await?["projection"],
        "not_projected"
    );
    sibling.project(&cancel).await?;
    a.ingest(batch("empty", 5, Body::Snapshot(vec![]))).await?;
    a.project(&cancel).await?;
    assert!(
        inspect(&a, "empty").await?["assets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inspect(&other, "first").await?["assets"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        inspect(&sibling, "first").await?["assets"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    other.close().await?;
    sibling.close().await?;
    rollback_and_unknown(&a).await?;
    a.close().await?;
    let restarted = app(scope(1, "d1")).await?;
    assert_eq!(restarted.project(&cancel).await?["applied"], 0);
    assert_eq!(
        inspect(&restarted, "receipt-unknown").await?["projection"],
        "projected"
    );
    restarted.close().await?;
    process_death(executable).await?;
    permissions_and_lifecycle().await?;
    Box::pin(filter_and_poison()).await?;
    Box::pin(cli_roundtrip(executable)).await?;
    Box::pin(admission_drift()).await?;
    Box::pin(invocation_horizon()).await?;
    Box::pin(empty_and_delete()).await?;
    Ok(())
}
struct RejectAfterWrite(Inventory<storage::Clock>);
impl PgEffect for RejectAfterWrite {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &rss_projection::ProjectionScope,
        event: &rss_projection::Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        self.0.apply(tx, scope, event).await?;
        Err(PgOperationError::rejected(
            rss_projection::Phase::Application,
            None,
            Some(event.position()),
            std::io::Error::other("fixture rejects after write to verify rollback"),
        ))
    }
}
async fn rollback_and_unknown(a: &App) -> Result<()> {
    let cancel = CancellationToken::new();
    let source = a.source()?;
    let scope = a.projection_scope();
    let before = inspect(a, "empty").await?;
    a.ingest(batch("rollback", 6, Body::Snapshot(facts("Recovered"))))
        .await?;
    let control = Control::new(&a.clock, a.clock.cutoff(storage::BUDGET), &cancel);
    let claim = a
        .projection
        .takeover(&scope, &definition(), &control)
        .await?;
    let execution = a
        .projection
        .projection(claim, RejectAfterWrite(Inventory::new(source.clone())))?;
    let report = rss_projection::run(
        source.as_ref(),
        &execution,
        &control,
        RunLimit::new(BatchLimit::new(10)?, 10)?,
    )
    .await;
    assert!(
        matches!(report.into_result(), Err(error) if error.kind() == rss_projection::ErrorKind::Rejected)
    );
    let failed = inspect(a, "rollback").await?;
    assert!(!failed["receipt"].is_null());
    assert_eq!(failed["projection"], "not_projected");
    assert_eq!(failed["assets"], before["assets"]);
    assert_eq!(failed["checkpoint"], before["checkpoint"]);
    drop(execution);
    assert_eq!(a.project(&cancel).await?["applied"], 1);
    // Receipt commit happened but both ACK and immediate readback are lost.
    let b = batch("receipt-unknown", 7, Body::Snapshot(facts("Unknown")));
    let authority = FixtureAuthority::new(scope_for_app());
    a.observation
        .inject_next_fault(rss_observation_postgres::Fault::CommitAckAndReadLost);
    let result = a
        .observation
        .receive(
            &VerifiedBatch::verify(&authority, scope_for_app(), b.clone())?,
            a.clock.deadline(),
        )
        .await;
    assert!(result.is_err());
    assert!(!inspect(a, "receipt-unknown").await?["receipt"].is_null());
    assert!(matches!(a.ingest(b).await?, ReceiveOutcome::Replay(_)));
    let control = Control::new(&a.clock, a.clock.cutoff(storage::BUDGET), &cancel);
    let claim = a
        .projection
        .takeover(&scope, &definition(), &control)
        .await?;
    let execution = a
        .projection
        .projection(claim, Inventory::new(source.clone()))?;
    let checkpoint = execution.checkpoint().await?;
    let events = source
        .read(source.scope(), checkpoint.position, BatchLimit::new(10)?)
        .await?;
    a.projection
        .inject_next_fault(rss_projection_postgres::PgFault::CommitUnknownAfterAck);
    assert!(
        execution
            .execute(checkpoint.position, &events[0], &control)
            .await
            .is_err()
    );
    drop(execution);
    let committed = inspect(a, "receipt-unknown").await?;
    assert_eq!(committed["projection"], "projected");
    assert_eq!(committed["assets"].as_array().unwrap().len(), 2);
    assert_eq!(a.project(&cancel).await?["applied"], 0);
    assert_eq!(inspect(a, "receipt-unknown").await?, committed);
    Ok(())
}
fn scope_for_app() -> Scope {
    scope(1, "d1")
}

async fn process_death(executable: &str) -> Result<()> {
    let a = app(scope(3, "crash")).await?;
    a.ingest(batch("crash", 0, Body::Snapshot(facts("AfterRestart"))))
        .await?;
    let owner = storage::pool(&url("MDM_OWNER_URL")?).await?;
    sqlx::raw_sql("CREATE FUNCTION mdm.pause_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2346001); PERFORM pg_sleep(25); RETURN NEW; END $$; CREATE TRIGGER pause_write AFTER INSERT ON mdm.inventory FOR EACH ROW EXECUTE FUNCTION mdm.pause_write();").execute(&owner).await?;
    let dir = std::env::temp_dir().join(format!("mdm-scope-{}.json", std::process::id()));
    std::fs::write(&dir, scope(3, "crash").encode()?)?;
    let mut child = std::process::Command::new(executable)
        .arg("project")
        .env("MDM_SCOPE_FILE", &dir)
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let admin = storage::pool(&url("MDM_ADMIN_URL")?).await?;
    let reached=tokio::time::timeout(Duration::from_secs(15),async {
        loop {
            let staged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=2346001 AND granted)").fetch_one(&admin).await?;
            if staged {return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await;
    child.kill()?;
    child.wait()?;
    std::fs::remove_file(dir)?;
    reached??;
    // Kill backend too: the client vanished during server pg_sleep; wait for rollback.
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND objid=2346001 AND granted").execute(&admin).await?;
    sqlx::raw_sql("DROP TRIGGER pause_write ON mdm.inventory; DROP FUNCTION mdm.pause_write();")
        .execute(&owner)
        .await?;
    let view = inspect(&a, "crash").await?;
    assert!(view["assets"].as_array().unwrap().is_empty());
    assert!(view["checkpoint"].is_null());
    a.close().await?;
    let restart = app(scope(3, "crash")).await?;
    assert_eq!(
        restart.project(&CancellationToken::new()).await?["applied"],
        1
    );
    restart.close().await?;
    storage::close_pool(&admin).await?;
    storage::close_pool(&owner).await?;
    Ok(())
}
async fn permissions_and_lifecycle() -> Result<()> {
    let options = storage::options()?;
    let pool = storage::pool(&options).await?;
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm.inventory")
        .fetch_one(&pool)
        .await?;
    assert_eq!(visible, 0);
    assert!(
        sqlx::query("CREATE TABLE public.forbidden(id int)")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM rss_observation.batches")
            .execute(&pool)
            .await
            .is_err()
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id','00000000-0000-0000-0000-000000000001',true)")
        .execute(&mut *tx)
        .await?;
    assert!(
        sqlx::query(
            "UPDATE mdm.inventory SET tenant_id='00000000-0000-0000-0000-000000000002'::uuid"
        )
        .execute(&mut *tx)
        .await
        .is_err()
    );
    tx.rollback().await?;
    storage::close_pool(&pool).await?;
    let a = app(scope(1, "d1")).await?;
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(a.project(&cancelled).await.is_err());
    a.close().await?;
    ensure!(a.observation.is_closed());
    assert!(a.inspect(&Id::new("first")?).await.is_err());
    // A borrowed connection prevents draining; deadline is not successful cleanup.
    let pool = storage::pool(&options).await?;
    let projection = rss_projection_postgres::PgStore::new(pool.clone()).await?;
    let held = pool.acquire().await?;
    let clock = system_clock();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_millis(20), &cancel);
    assert_eq!(
        projection.close(&control).await,
        rss_projection_postgres::CloseOutcome::Deadline
    );
    drop(held);
    drop(pool);
    assert_eq!(
        projection
            .close(&Control::new(&clock, storage::BUDGET, &cancel))
            .await,
        rss_projection_postgres::CloseOutcome::Drained
    );
    let bad = options.clone().password("wrong");
    assert!(
        App::open(&bad, FixtureAuthority::new(scope(1, "d1")), system_clock())
            .await
            .is_err()
    );
    let bad = options.ssl_root_cert_from_pem(b"not a certificate".to_vec());
    assert!(
        App::open(&bad, FixtureAuthority::new(scope(1, "d1")), system_clock())
            .await
            .is_err()
    );
    Ok(())
}

// Test producer deliberately exercises product projection validation independently
// of ingest's own validation. It grants exactly one scope, never arbitrary tenants.
struct JournalFixture(Scope);
impl rss_observation::Authority for JournalFixture {
    fn authorize(&self, access: rss_observation::Access<'_>) -> Result<(), rss_observation::Error> {
        let allowed = match access {
            rss_observation::Access::Activate { scope }
            | rss_observation::Access::Submit { scope, .. } => scope == &self.0,
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
#[allow(
    clippy::disallowed_methods,
    reason = "Real PG poison fixture timestamp must track server wall time"
)]
async fn filter_and_poison() -> Result<()> {
    let a = app(scope(4, "validation")).await?;
    let s = scope(4, "not-inventory");
    let s: Scope = serde_json::from_str(
        &s.encode()?
            .replace("\"dataset\":\"inventory\"", "\"dataset\":\"other\""),
    )?;
    let producer = JournalFixture(s.clone());
    a.observation
        .activate(
            &rss_observation::LifecycleGrant::verify(&producer, s.clone())?,
            None,
            &rss_observation::Policy::new(86400, 3600, 3600)?,
            a.clock.deadline(),
        )
        .await?;
    a.observation
        .receive(
            &VerifiedBatch::verify(
                &producer,
                s,
                batch("other", 0, Body::Snapshot(facts("Other"))),
            )?,
            a.clock.deadline(),
        )
        .await?;
    let cancel = CancellationToken::new();
    assert_eq!(a.project(&cancel).await?["filtered"], 1);
    let s = scope(4, "validation");
    let producer = JournalFixture(s.clone());
    a.observation
        .activate(
            &rss_observation::LifecycleGrant::verify(&producer, s.clone())?,
            None,
            &rss_observation::Policy::new(86400, 3600, 3600)?,
            a.clock.deadline(),
        )
        .await?;
    let bad = rss_observation::Coverage::new(
        Id::new("device-basics")?,
        Id::new("2")?,
        Id::new("model-os")?,
        Id::new("unknown")?,
    );
    let b = Batch::new(
        Id::new("poison")?,
        0,
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
        bad,
        Body::Snapshot(facts("Invalid")),
    )?;
    a.observation
        .receive(&VerifiedBatch::verify(&producer, s, b)?, a.clock.deadline())
        .await?;
    let before = inspect(&a, "poison").await?;
    assert!(a.project(&cancel).await.is_err());
    assert_eq!(inspect(&a, "poison").await?, before);
    a.close().await?;
    Ok(())
}
async fn cli_roundtrip(executable: &str) -> Result<()> {
    let dir = std::env::temp_dir().join(format!("mdm-cli-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("scope.json"), scope(5, "cli").encode()?)?;
    std::fs::write(
        dir.join("batch.json"),
        batch("cli", 0, Body::Snapshot(facts("CLI"))).encode(),
    )?;
    let call = |args: Vec<String>| -> Result<serde_json::Value> {
        let output = std::process::Command::new(executable)
            .args(args)
            .env("MDM_SCOPE_FILE", dir.join("scope.json"))
            .output()?;
        ensure!(
            output.status.success(),
            "CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    };
    assert_eq!(
        call(vec![
            "ingest-fixture".into(),
            dir.join("batch.json").to_string_lossy().into_owned()
        ])?["receipt"],
        "accepted"
    );
    assert_eq!(call(vec!["project".into()])?["applied"], 1);
    assert_eq!(
        call(vec!["inspect".into(), "cli".into()])?["assets"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let bad = std::process::Command::new(executable)
        .arg("inspect")
        .arg("cli")
        .env("MDM_SCOPE_FILE", dir.join("scope.json"))
        .env(
            "DATABASE_URL",
            "postgres://invalid:SECRET@localhost:1/missing",
        )
        .output()?;
    assert!(!bad.status.success());
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("SECRET"));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

async fn admission_drift() -> Result<()> {
    let owner = storage::pool(&url("MDM_OWNER_URL")?).await?;
    let admin = storage::pool(&url("MDM_ADMIN_URL")?).await?;
    for (damage, restore) in [
        (
            "ALTER TABLE mdm.inventory NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm.inventory FORCE ROW LEVEL SECURITY",
        ),
        (
            "ALTER TABLE mdm.inventory DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm.inventory ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant ON mdm.inventory USING (true)",
            "ALTER POLICY tenant ON mdm.inventory USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "GRANT CREATE ON SCHEMA mdm TO mdm_runtime",
            "REVOKE CREATE ON SCHEMA mdm FROM mdm_runtime",
        ),
        (
            "GRANT SELECT ON mdm.inventory TO PUBLIC",
            "REVOKE SELECT ON mdm.inventory FROM PUBLIC",
        ),
        (
            "GRANT TRIGGER ON mdm.inventory TO mdm_runtime",
            "REVOKE TRIGGER ON mdm.inventory FROM mdm_runtime",
        ),
    ] {
        sqlx::raw_sql(damage).execute(&owner).await?;
        let result = app(scope(1, "d1")).await;
        sqlx::raw_sql(restore).execute(&owner).await?;
        if let Ok(a) = result {
            a.close().await?;
            anyhow::bail!("Inventory admission accepted {damage}");
        }
    }
    sqlx::raw_sql("GRANT mdm_owner TO mdm_runtime")
        .execute(&admin)
        .await?;
    let denied = app(scope(1, "d1")).await;
    sqlx::raw_sql("REVOKE mdm_owner FROM mdm_runtime")
        .execute(&admin)
        .await?;
    assert!(denied.is_err());
    let source = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let offset = source.clone();
    let real = system_clock();
    let injected = storage::Clock::new(move || {
        real.now() + Duration::from_secs(offset.load(std::sync::atomic::Ordering::SeqCst))
    });
    let aged = App::open(
        &storage::options()?,
        FixtureAuthority::new(scope(1, "d1")),
        injected,
    )
    .await?;
    source.store(60, std::sync::atomic::Ordering::SeqCst);
    aged.project(&CancellationToken::new()).await?;
    aged.inspect(&Id::new("first")?).await?;
    aged.close().await?;
    storage::close_pool(&owner).await?;
    storage::close_pool(&admin).await?;
    Ok(())
}

async fn invocation_horizon() -> Result<()> {
    let a = std::sync::Arc::new(app(scope(6, "window")).await?);
    for sequence in 0..257 {
        a.ingest(batch(
            &format!("window-{sequence}"),
            sequence,
            Body::Snapshot(facts("Window")),
        ))
        .await?;
    }
    let owner = storage::pool(&url("MDM_OWNER_URL")?).await?;
    let admin = storage::pool(&url("MDM_ADMIN_URL")?).await?;
    sqlx::raw_sql("CREATE FUNCTION mdm.window_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.batch_id='window-0' THEN PERFORM pg_advisory_xact_lock(2346002); PERFORM pg_sleep(0.3); END IF; RETURN NEW; END $$; CREATE TRIGGER window_pause AFTER INSERT ON mdm.inventory FOR EACH ROW EXECUTE FUNCTION mdm.window_pause();").execute(&owner).await?;
    let worker_app = a.clone();
    let worker = tokio::spawn(async move { worker_app.project(&CancellationToken::new()).await });
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            let staged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=2346002 AND granted)").fetch_one(&admin).await?;
            if staged {return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    a.ingest(batch(
        "window-later",
        257,
        Body::Snapshot(facts("NextInvocation")),
    ))
    .await?;
    let first = tokio::time::timeout(Duration::from_secs(30), worker).await???;
    assert_eq!(first["applied"], 257);
    assert_eq!(first["position"], first["through"]);
    assert_eq!(a.project(&CancellationToken::new()).await?["applied"], 1);
    sqlx::raw_sql("DROP TRIGGER window_pause ON mdm.inventory; DROP FUNCTION mdm.window_pause();")
        .execute(&owner)
        .await?;
    a.close().await?;
    storage::close_pool(&owner).await?;
    storage::close_pool(&admin).await?;
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "Real PG scenario composition root chooses a monotonic clock"
)]
fn system_clock() -> storage::Clock {
    storage::Clock::new(std::time::Instant::now)
}

async fn empty_and_delete() -> Result<()> {
    let a = app(scope(7, "empty")).await?;
    let cancel = CancellationToken::new();
    assert_eq!(inspect(&a, "missing").await?["projection"], "not_projected");
    a.ingest(batch("empty", 0, Body::Snapshot(vec![]))).await?;
    let before = inspect(&a, "empty").await?;
    assert_eq!(before["projection"], "not_projected");
    a.project(&cancel).await?;
    let after = inspect(&a, "empty").await?;
    assert_eq!(after["assets"], before["assets"]);
    assert_eq!(after["projection"], "projected");
    a.ingest(batch("populated", 1, Body::Snapshot(facts("Delete"))))
        .await?;
    a.project(&cancel).await?;
    a.ingest(batch(
        "delete",
        2,
        Body::Delta {
            baseline: Id::new("populated")?,
            previous: 1,
            changes: vec![
                Change::delete(Id::new("device.model")?),
                Change::delete(Id::new("device.os.version")?),
            ],
        },
    ))
    .await?;
    assert_eq!(inspect(&a, "delete").await?["projection"], "not_projected");
    a.project(&cancel).await?;
    let view = inspect(&a, "delete").await?;
    assert!(view["assets"].as_array().unwrap().is_empty());
    assert_eq!(view["projection"], "projected");
    a.close().await?;
    Ok(())
}
