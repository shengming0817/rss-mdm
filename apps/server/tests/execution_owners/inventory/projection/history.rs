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
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            h.c.inputs
                .options(&h.c.profile, "mdm_runtime")?
                .username("mdm_observation_maintenance"),
        )
        .await?;
    let maintenance =
        rss_observation_postgres::PgMaintenance::new(pool.clone(), page.clock.clone(), deadline)
            .await?;
    let authorized = MaintenanceGrant::verify(&claim, scope.clone(), cutoff, 2)?;
    let outcome = maintenance
        .reclaim(authorized, ScanWindow::new(None, 8)?, deadline)
        .await?;
    anyhow::ensure!(outcome.reclaimed == 3);
    pool.close().await;
    expired_receipts(page, deadline).await
}
async fn expired_receipts(page: &Page, deadline: rss_request_context::Deadline) -> Result<()> {
    let scope = &page.stream.0;
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

struct FirstWrite {
    effect: rss_mdm_inventory_postgres::Inventory<rt::Clock>,
    written: CancellationToken,
    released: CancellationToken,
}
impl rss_projection_postgres::PgEffect for FirstWrite {
    type Item = rss_projection::EventWith<rss_observation_postgres::VerifiedObservation>;
    const ISOLATION: rss_projection_postgres::EffectIsolation =
        rss_projection_postgres::EffectIsolation::ReadCommitted;
    async fn apply(
        &self,
        tx: &mut rss_projection_postgres::PgTransaction<'_>,
        scope: &rss_projection::ProjectionScope,
        event: &Self::Item,
    ) -> std::result::Result<
        rss_projection_postgres::PgEffectOutcome,
        rss_projection_postgres::PgOperationError,
    > {
        let outcome = self.effect.apply(tx, scope, event).await?;
        if event.as_ref().position().get() == 1 {
            self.written.cancel();
            self.released.cancelled().await;
        }
        Ok(outcome)
    }
}
pub(super) struct Baseline {
    last_report: String,
    snapshot: Value,
    receipts: Vec<BaselineReceipt>,
}
pub(super) async fn exercise(
    h: &Harness,
    page: &Page,
    store: &rss_projection_postgres::PgStore,
) -> Result<Baseline> {
    let baseline = baseline(h, page, store).await?;
    released_page(h, page).await?;
    Ok(baseline)
}
async fn baseline(
    h: &Harness,
    page: &Page,
    store: &rss_projection_postgres::PgStore,
) -> Result<Baseline> {
    reset(h).await?;
    let token = CancellationToken::new();
    let control = page.control(&token);
    let worker = page
        .worker(h, store, GenerationStart::beginning(), &control)
        .await?;
    let events = page
        .source
        .read(
            page.scope.source(),
            None,
            PageBudget::new(2, rss_projection::Event::MAX_PAYLOAD_BYTES)?,
            &control,
        )
        .await?;
    let rss_projection::ReadPage::Events(events) = events else {
        anyhow::bail!("expected prefix events");
    };
    assert_eq!(events.len(), 2);
    let prefix = rss_projection::run_batched(
        &*page.source,
        &worker,
        &control,
        RunLimit::new(
            PageBudget::new(2, rss_projection::Event::MAX_PAYLOAD_BYTES)?,
            2,
        )?,
    )
    .await
    .into_result()?;
    assert_eq!(prefix.position, Some(Position::new(2)?));
    let receipts = events
        .iter()
        .map(|item| BaselineReceipt::from_event(item.as_ref()))
        .collect::<Vec<_>>();
    let snapshot: Value =
        sqlx::query_scalar("SELECT to_jsonb(i) FROM mdm.inventory i WHERE tenant_id=$1::uuid")
            .bind(h.c.tenant.to_string())
            .fetch_one(&h.c.operator)
            .await?;
    assert_eq!(snapshot["batch_id"], page.reports[2].id().as_str());
    let (scope, last) = sealed(
        h,
        false,
        NativeValue::Value(CollectedValue::Value(Scalar::Boolean(false))),
    )
    .await?;
    let verified = VerifiedBatch::verify(&page.stream, scope, last.clone())?;
    let deadline = rss_request_context::Deadline::at(
        rss_observation::Clock::now(&page.clock) + Duration::from_secs(5),
    );
    assert!(
        page.observation
            .receive(&verified, deadline)
            .await?
            .record()
            .decision()
            .outcome()
            .is_applicable()
    );
    Ok(Baseline {
        snapshot,
        receipts,
        last_report: last.id().as_str().into(),
    })
}
async fn released_page(h: &Harness, page: &Page) -> Result<()> {
    let token = CancellationToken::new();
    let control = page.control(&token);
    let after = reset(h).await?;
    let effect_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(h.c.inputs.options(&h.c.profile, "mdm_runtime")?)
        .await?;
    let effect_store = rss_projection_postgres::PgStore::new(effect_pool.clone(), &control).await?;
    let definition = rss_mdm_inventory_postgres::definition();
    effect_store
        .initialize(
            &page.scope,
            &definition,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let written = CancellationToken::new();
    let released = CancellationToken::new();
    let lagging = effect_store.projection(
        effect_store
            .takeover(&page.scope, &definition, &control)
            .await?,
        FirstWrite {
            effect: rss_mdm_inventory_postgres::Inventory::new(
                page.source.clone(),
                h.c.execution(),
            ),
            written: written.clone(),
            released: released.clone(),
        },
    )?;
    let reclaim = async {
        tokio::time::timeout(Duration::from_secs(20), written.cancelled()).await?;
        let result = release(h, page).await;
        released.cancel();
        result
    };
    let (failed, reclaimed) = tokio::join!(
        rss_projection::run_batched(&*page.source, &lagging, &control, limit()?),
        reclaim
    );
    reclaimed?;
    verify_released(h, page, failed, after, &control).await?;
    let retry = rss_projection::run_batched(&*page.source, &lagging, &control, limit()?).await;
    assert_eq!(
        retry.into_result().unwrap_err().kind(),
        rss_projection::ErrorKind::HistoryExpired
    );
    effect_pool.close().await;
    Ok(())
}

async fn verify_released(
    h: &Harness,
    page: &Page,
    failed: rss_projection::Report,
    after: i64,
    control: &Control<'_, rt::Clock>,
) -> Result<()> {
    let Stop::Failed(error) = failed.stop else {
        anyhow::bail!("released page completed")
    };
    assert_eq!(error.kind(), rss_projection::ErrorKind::HistoryExpired);
    assert_eq!(
        error.diagnostic().and_then(|d| d.position()),
        Some(Position::new(2)?)
    );
    assert_eq!((failed.position, failed.applied), (None, 0));
    assert_eq!(progress(&h.c).await?, (None, 0, 0));
    assert!(business(&h.c, after).await?.0.is_empty());
    assert_eq!(
        page.source.bounds(control).await?.expired_through,
        Some(Position::new(2)?)
    );
    Ok(())
}

pub(super) async fn restore(
    tenant: rss_request_context::TenantId,
    page: &Page,
    baseline: Baseline,
) -> Result<()> {
    use crate::authority_t2_support::Inputs;
    let mut inputs = Inputs::load()?;
    let profile = "inventory_capacity";
    let original = inputs.database(profile, "postgres");
    // This profile is a disposable database owned by this test environment.
    let source = original
        .name
        .strip_prefix("t2_")
        .ok_or_else(|| anyhow::anyhow!("expected a disposable source database"))?;
    let source = Uuid::parse_str(source)?.simple();
    let target = format!("t2_restore_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(original.options()?.database("postgres"))
        .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE {target} TEMPLATE t2_{source}"
    )))
    .execute(&admin)
    .await?;
    let result = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        for db in inputs.databases.get_mut(profile).unwrap().values_mut() {
            db.name = target.clone();
        }
        let operator = inputs.pool(profile, "postgres").await?;
        let c = Context::connect(
            profile,
            inputs,
            operator,
            tenant,
            &crate::config::AuditConfig::Plain,
        )
        .await?;
        let result = resume(&c, page, baseline).await;
        c.close().await;
        result
    }))
    .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {target} WITH (FORCE)"
    )))
    .execute(&admin)
    .await?;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic))?;
    let source = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(original.options()?)
        .await?;
    let original_checkpoint:Option<i64>=sqlx::query_scalar("SELECT position FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND projection_id='inventory'").bind(tenant.to_string()).fetch_one(&source).await?;
    assert_eq!(original_checkpoint, None);
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm.inventory WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&source)
            .await?;
    assert_eq!(remaining, 0);
    source.close().await;
    admin.close().await;
    Ok(())
}

async fn resume(c: &Context, page: &Page, baseline: Baseline) -> Result<()> {
    let clock = &page.clock;
    let token = CancellationToken::new();
    let control = page.control(&token);
    let options = c.inputs.options(&c.profile, "mdm_runtime")?;
    let observation = rt::ObservationResource::open(options.clone(), clock.clone()).await?;
    let last_report = baseline.last_report.clone();
    refuse_empty_start(c, page, &observation).await?;
    install_baseline(c, page, baseline, &control).await?;
    let restoration = sqlx::query_scalar::<_, i64>(
        "SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    for _ in 0..2 {
        resume_once(c, clock, &observation.store, Some(4)).await?;
    }
    let (rows, xids) = business(c, restoration).await?;
    assert_eq!((rows.len(), xids), (2, 1));
    assert_eq!(rows[0]["batch_id"], page.reports[3].id().as_str());
    assert_eq!(rows[1]["batch_id"], last_report);
    assert_eq!(progress(c).await?, (Some(4), 4, 1));
    rss_runtime::ManagedResource::shutdown(&observation).await?;
    Ok(())
}

async fn refuse_empty_start(
    c: &Context,
    page: &Page,
    observation: &rt::ObservationResource,
) -> Result<()> {
    let clock = &page.clock;
    let removed=sqlx::query("DELETE FROM rss_projection.checkpoints c WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id=$3 AND generation=$4 AND position IS NULL AND NOT EXISTS(SELECT FROM rss_projection.receipts r WHERE (r.tenant_id,r.source_id,r.projection_id,r.generation)=(c.tenant_id,c.source_id,c.projection_id,c.generation))")
        .bind(c.tenant.to_string()).bind(page.scope.source().source()).bind(page.scope.projection()).bind(page.scope.generation()).execute(&c.operator).await?;
    assert_eq!(removed.rows_affected(), 1);
    resume_once(c, clock, &observation.store, None).await?;
    let empty:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid) AND NOT EXISTS(SELECT FROM mdm.inventory WHERE tenant_id=$1::uuid)").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    anyhow::ensure!(
        empty,
        "worker must refuse a beginning below the retained floor"
    );
    Ok(())
}

async fn install_baseline(
    c: &Context,
    page: &Page,
    baseline: Baseline,
    control: &Control<'_, rt::Clock>,
) -> Result<()> {
    let options = c.inputs.options(&c.profile, "mdm_runtime")?;
    let mut restore = command::seed_transaction(c).await?;
    sqlx::query(
        "INSERT INTO mdm.inventory SELECT * FROM jsonb_populate_record(NULL::mdm.inventory,$1)",
    )
    .bind(baseline.snapshot)
    .execute(&mut *restore)
    .await?;
    restore.commit().await?;
    let initial = rt::ProjectionResource::open(options, page.clock.clone(), control).await?;
    initial
        .store
        .initialize(
            &page.scope,
            &rss_mdm_inventory_postgres::definition(),
            GenerationStart::after(Position::new(2)?, baseline.receipts)?,
            ReplayBound::Live,
            control,
        )
        .await?;
    rss_runtime::ManagedResource::shutdown(&initial).await?;
    Ok(())
}

pub(super) async fn resume_once(
    c: &Context,
    clock: &rt::Clock,
    observation: &Arc<Store>,
    expected_head: Option<u64>,
) -> Result<()> {
    let (inventory, resource) = open_worker(c, clock, observation).await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_resource(rss_runtime::DynManagedResource::new_box(resource));
    let notify = Arc::new(tokio::sync::Notify::new());
    launch.stage_task_with_token(inventory.clone().registration(notify.clone()));
    launch.finish();
    tokio::time::timeout(Duration::from_secs(40),async {
        loop {
            let d=inventory.diagnostics(c.execution(),rss_observation::Clock::now(clock)+Duration::from_secs(5)).await;
            let reached=match expected_head {
                None=>d.baseline_required,
                Some(head)=>matches!(d.projection,Some(rss_projection::ObservationStatus::Stopped(ref run)) if run.stop==Stop::CaughtUp && run.position.map(|p|p.get())==Some(head)),
            };
            if reached && matches!(d.delivery,Ok(0)) {break}
            notify.notify_one();
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    anyhow::ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}

pub(super) async fn open_worker(
    c: &Context,
    clock: &rt::Clock,
    observation: &Arc<Store>,
) -> Result<(Arc<rt::InventoryRuntime>, rt::ProjectionResource)> {
    let token = CancellationToken::new();
    let control = Control::new(clock, clock.startup_cutoff(), &token);
    let options = c.inputs.options(&c.profile, "mdm_runtime")?;
    let resource = rt::ProjectionResource::open(options.clone(), clock.clone(), &control).await?;
    let inventory = Arc::new(rt::InventoryRuntime::new(
        observation.clone(),
        resource.store.clone(),
        c.database.inventory(),
        c.database.long_operations.clone(),
        c.audit.clone(),
        c.execution().storage(),
        c.execution().epoch(),
        clock.clone(),
        Arc::default(),
    ));
    Ok((inventory, resource))
}
