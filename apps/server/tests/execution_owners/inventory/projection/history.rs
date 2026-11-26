use super::*;
use rss_observation::{
    LookupOutcome, MaintenanceGrant, ObservationMaintenance as _, ReadGrant, ScanWindow,
};
use rss_projection::{BaselineReceipt, Position, Stop};

struct Release<'a> {
    stream: &'a Stream,
    cutoff: i64,
}
impl Authority for Release<'_> {
    fn authorize(&self, access: Access<'_>) -> std::result::Result<(), rss_observation::Error> {
        if matches!(access,Access::Maintain {scope,cutoff,release_through:2} if scope == &self.stream.0 && cutoff==self.cutoff)
        {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
async fn release(h: &Harness, page: &Page) -> Result<()> {
    let scope = &page.stream.0;
    let deadline = rss_request_context::Deadline::at(
        rss_observation::Clock::now(&page.clock) + Duration::from_secs(30),
    );
    let policy = rss_observation::Policy::new(86400, 3600, 3600)?;
    let next = rss_observation::Scope::new(
        scope.tenant(),
        scope.object().clone(),
        scope.registration().clone(),
        scope.source().clone(),
        scope.dataset().clone(),
        rss_observation::Epoch::new(Uuid::new_v4().to_string())?,
    );
    page.observation
        .activate(
            &LifecycleGrant::verify(&Stream(next.clone()), next)?,
            Some(1),
            &policy,
            deadline,
        )
        .await?;
    // Age only the disposable prefix; the maintenance owner still checks retirement,
    // the receipt window and the protected coverage before releasing any body.
    let cutoff = now();
    sqlx::query("UPDATE rss_observation.batches SET received_at=$2 WHERE tenant_id=$1::uuid AND sequence <= $3")
        .bind(h.c.tenant.to_string()).bind(cutoff-86400-3601).bind(i64::try_from(page.reports[2].sequence())?).execute(&h.c.operator).await?;
    let claim = Release {
        stream: &page.stream,
        cutoff,
    };
    let role = format!("obs_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} LOGIN PASSWORD '{password}'; GRANT USAGE ON SCHEMA rss_observation TO {role}; GRANT EXECUTE ON FUNCTION rss_observation.reclaim(text,bigint,bigint,numeric,integer) TO {role}")))
        .execute(&h.c.operator).await?;
    let result = async {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(
                h.c.inputs
                    .options(&h.c.profile, "mdm_runtime")?
                    .username(&role)
                    .password(&password),
            )
            .await?;
        let maintenance = rss_observation_postgres::PgMaintenance::new(
            pool.clone(),
            page.clock.clone(),
            deadline,
        )
        .await?;
        let authorized = MaintenanceGrant::verify(&claim, scope.clone(), cutoff, 2)?;
        let outcome = maintenance
            .reclaim(authorized, ScanWindow::new(None, 8)?, deadline)
            .await?;
        anyhow::ensure!(outcome.reclaimed == 3);
        pool.close().await;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP OWNED BY {role}; DROP ROLE {role}"
    )))
    .execute(&h.c.operator)
    .await?;
    result?;
    let read = ReadGrant::verify(&page.stream, scope.clone())?;
    let batch = &page.reports[0];
    assert!(matches!(
        page.observation.lookup(&read, batch.id(), deadline).await?,
        LookupOutcome::Expired
    ));
    assert!(matches!(
        page.observation
            .lookup(&read, &rss_observation::Id::new("absent")?, deadline)
            .await?,
        LookupOutcome::NotFound
    ));
    let original = VerifiedBatch::verify(&page.stream, scope.clone(), batch.clone())?;
    assert_eq!(
        page.observation
            .receive(&original, deadline)
            .await
            .unwrap_err()
            .kind(),
        rss_observation::ErrorKind::HistoryExpired
    );
    let changed = rss_observation::Batch::new(
        batch.id().clone(),
        batch.sequence(),
        rss_contract::Timepoint::try_from(batch.observed_at_seconds() + 1)?,
        batch.coverage().clone(),
        batch.body().clone(),
    )?;
    let changed = VerifiedBatch::verify(&page.stream, scope.clone(), changed)?;
    assert_eq!(
        page.observation
            .receive(&changed, deadline)
            .await
            .unwrap_err()
            .kind(),
        rss_observation::ErrorKind::Conflict
    );
    Ok(())
}

pub(super) async fn exercise(
    h: &Harness,
    page: &Page,
    store: &rss_projection_postgres::PgStore,
) -> Result<()> {
    reset(h).await?;
    let token = CancellationToken::new();
    let control = page.control(&token);
    let worker = page
        .worker(h, store, GenerationStart::beginning(), &control)
        .await?;
    let events = page
        .source
        .read(page.scope.source(), None, BatchLimit::new(2)?, &control)
        .await?;
    assert_eq!(events.len(), 2);
    let prefix = rss_projection::run_batched(
        &*page.source,
        &worker,
        &control,
        RunLimit::new(BatchLimit::new(2)?, 2)?,
    )
    .await
    .into_result()?;
    assert_eq!(prefix.position, Some(Position::new(2)?));
    let receipts = events
        .iter()
        .map(BaselineReceipt::from_event)
        .collect::<Vec<_>>();
    let snapshot: Value =
        sqlx::query_scalar("SELECT to_jsonb(i) FROM mdm.inventory i WHERE tenant_id=$1::uuid")
            .bind(h.c.tenant.to_string())
            .fetch_one(&h.c.operator)
            .await?;
    assert_eq!(snapshot["batch_id"], page.reports[2].id().as_str());
    release(h, page).await?;
    assert_eq!(
        page.source.bounds(&control).await?.expired_through,
        Some(Position::new(2)?)
    );
    let old = rss_projection::ProjectionScope::new(
        page.scope.source().clone(),
        page.scope.projection(),
        "outdated",
    )?;
    let definition = rss_mdm_inventory_postgres::definition();
    store
        .initialize(
            &old,
            &definition,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let lagging = store.projection(
        store.takeover(&old, &definition, &control).await?,
        rss_mdm_inventory_postgres::Inventory::new(page.source.clone(), h.c.execution()),
    )?;
    let failed = rss_projection::run_batched(&*page.source, &lagging, &control, limit()?).await;
    assert!(
        matches!(failed.stop, Stop::Failed(ref e) if e.kind()==rss_projection::ErrorKind::HistoryExpired)
    );
    assert_eq!((failed.position, failed.applied), (None, 0));
    reset(h).await?;
    let mut restore = command::seed_transaction(&h.c).await?;
    sqlx::query(
        "INSERT INTO mdm.inventory SELECT * FROM jsonb_populate_record(NULL::mdm.inventory,$1)",
    )
    .bind(snapshot)
    .execute(&mut *restore)
    .await?;
    restore.commit().await?;
    store
        .initialize(
            &page.scope,
            &definition,
            GenerationStart::after(Position::new(2)?, receipts)?,
            ReplayBound::Live,
            &control,
        )
        .await?;

    let restoration = sqlx::query_scalar::<_, i64>(
        "SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id=$1::uuid",
    )
    .bind(h.c.tenant.to_string())
    .fetch_one(&h.c.operator)
    .await?;
    for _ in 0..2 {
        let resource = rt::ProjectionResource::open(
            h.c.inputs.options(&h.c.profile, "mdm_runtime")?,
            page.clock.clone(),
            &control,
        )
        .await?;
        let inventory = Arc::new(rt::InventoryRuntime::new(
            page.observation.clone(),
            resource.store.clone(),
            h.c.database.inventory(),
            h.c.database.long_operations.clone(),
            h.audit.clone(),
            h.c.execution().storage(),
            h.c.execution().epoch(),
            page.clock.clone(),
            Arc::default(),
        ));
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = stack.startup()?.commit();
        launch.stage_resource(rss_runtime::DynManagedResource::new_box(resource));
        launch.stage_task_with_token(
            inventory
                .clone()
                .registration(Arc::new(tokio::sync::Notify::new())),
        );
        launch.finish();
        let last = &page.reports[3];
        report_committed(h, Uuid::parse_str(last.id().as_str())?, last.id().as_str()).await?;
        let audit = async {
            loop {
                let d = inventory
                    .diagnostics(
                        h.c.execution(),
                        rss_observation::Clock::now(&page.clock) + Duration::from_secs(5),
                    )
                    .await;
                if matches!(d.projection,Some(rss_projection::ObservationStatus::Stopped(ref run)) if run.stop==Stop::CaughtUp && run.position==Some(Position::new(3)?))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::time::timeout(Duration::from_secs(25), audit).await??;
        anyhow::ensure!(stack.shutdown().join().await?.is_clean());
    }
    let (rows, xids) = business(h, restoration).await?;
    assert_eq!((rows.len(), xids), (1, 1));
    assert_eq!(rows[0]["batch_id"], page.reports[3].id().as_str());
    assert_eq!(progress(h).await?, (Some(3), 3, 1));
    Ok(())
}
