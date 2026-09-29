use super::*;
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
    let clock = system_clock();
    let cancel = CancellationToken::new();
    let startup = Control::new(&clock, clock.cutoff(storage::BUDGET), &cancel);
    let projection = rss_projection_postgres::PgStore::new(pool.clone(), &startup).await?;
    let held = pool.acquire().await?;
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

#[tokio::test]
#[ignore = "MODULE=inventory.recovery: real PostgreSQL"]
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

#[tokio::test]
#[ignore = "MODULE=inventory.recovery: real PostgreSQL"]
async fn receipt_and_projection_commit_recovery() -> Result<()> {
    let a = app(scope_for_app()).await?;
    let cancel = CancellationToken::new();
    a.ingest(batch("empty", 5, Body::Snapshot(vec![]))).await?;
    a.project(&cancel).await?;
    rollback_and_unknown(&a).await?;
    a.close().await?;
    let restarted = app(scope_for_app()).await?;
    assert_eq!(restarted.project(&cancel).await?["applied"], 0);
    assert_eq!(
        inspect(&restarted, "receipt-unknown").await?["projection"],
        "projected"
    );
    restarted.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=inventory.recovery: real PostgreSQL"]
async fn permissions_and_bounded_lifecycle() -> Result<()> {
    let a = app(scope_for_app()).await?;
    a.ingest(batch("first", 0, Body::Snapshot(facts("lifecycle"))))
        .await?;
    a.project(&CancellationToken::new()).await?;
    a.close().await?;
    permissions_and_lifecycle().await
}
