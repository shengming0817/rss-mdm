//! Product report intake and the real Inventory effect on the same installed database.
use super::*;
use anyhow::Result;
use rss_mdm_inventory_service::inventory_runtime as rt;
use rss_observation::{
    Access, Authority, JournalReadGrant, LifecycleGrant, ObservationStore, VerifiedBatch,
};
use rss_projection::{
    BatchLimit, Control, GenerationStart, ReplayBound, RunLimit, Source as _, Timer as _,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{collections::BTreeMap, time::Duration};
use tokio_util::sync::CancellationToken;
mod history;
mod settlement;

struct Stream(rss_observation::Scope);
impl Authority for Stream {
    fn authorize(&self, access: Access<'_>) -> std::result::Result<(), rss_observation::Error> {
        let allowed = match access {
            Access::Activate { scope } | Access::Read { scope } | Access::Submit { scope, .. } => {
                scope == &self.0
            }
            Access::ReadJournal { tenant } => tenant == self.0.tenant(),
            Access::Maintain { .. } => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
type Store = rss_observation_postgres::PgStore<rt::Clock>;
type Source = rss_observation_postgres::PgSource<rt::Clock>;
type Worker =
    rss_projection_postgres::PgProjection<rss_mdm_inventory_postgres::Inventory<rt::Clock>>;
struct Page {
    clock: rt::Clock,
    observation: Arc<Store>,
    source: Arc<Source>,
    stream: Stream,
    scope: rss_projection::ProjectionScope,
    reports: Vec<rss_observation::Batch>,
}
impl Page {
    async fn prepare(h: &Harness, pool: &PgPool) -> Result<Self> {
        let clock = rt::Clock::new(
            crate::clock::monotonic(),
            h.a.resources.config.inventory_runtime.compile()?,
        );
        let deadline = rss_request_context::Deadline::at(
            rss_observation::Clock::now(&clock) + Duration::from_secs(90),
        );
        let observation = Arc::new(Store::new(pool.clone(), clock.clone(), deadline).await?);
        let mut reports = Vec::new();
        let mut stream = None;
        for (i, value) in [Some(true), None, Some(false), Some(true)]
            .into_iter()
            .enumerate()
        {
            let (id, _, _) = report_value(
                h,
                i == 0,
                value.map_or(NativeValue::Failed, |v| {
                    NativeValue::Value(CollectedValue::Value(Scalar::Boolean(v)))
                }),
            )
            .await?;
            let mut tx = command::seed_transaction(&h.c).await?;
            let run = rss_mdm_inventory_service::collection::store::read_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                &mut tx,
                &h.c.tenant.to_string(),
                id,
            )
            .await?;
            tx.commit().await?;
            let authority = stream.get_or_insert_with(|| Stream(run.scope.clone()));
            assert_eq!(authority.0, run.scope);
            reports.push(run.batch().unwrap().clone());
        }
        let stream = stream.unwrap();
        observation
            .activate(
                &LifecycleGrant::verify(&stream, stream.0.clone())?,
                None,
                &rss_observation::Policy::new(86400, 3600, 3600)?,
                deadline,
            )
            .await?;
        // RSS sees a reference snapshot even for a failed collection. Deliver one
        // older sealed snapshot late to obtain a real, non-applicable Stale receipt.
        for index in [0, 2, 1, 3] {
            let verified =
                VerifiedBatch::verify(&stream, stream.0.clone(), reports[index].clone())?;
            let accepted = observation.receive(&verified, deadline).await?;
            assert_eq!(
                accepted.record().decision().outcome().is_applicable(),
                index != 1
            );
            assert!(matches!(
                observation.receive(&verified, deadline).await?,
                rss_observation::ReceiveOutcome::Replay(_)
            ));
        }
        let scope = rss_mdm_inventory_postgres::projection_scope(h.c.tenant);
        let source = Arc::new(Source::new(
            observation.clone(),
            JournalReadGrant::verify(&stream, h.c.tenant)?,
            scope.source().clone(),
        )?);
        Ok(Self {
            clock,
            observation,
            source,
            stream,
            scope,
            reports,
        })
    }
    fn control<'a>(&'a self, token: &'a CancellationToken) -> Control<'a, rt::Clock> {
        Control::new(
            &self.clock,
            self.clock.now() + Duration::from_secs(50),
            token,
        )
    }
    async fn worker(
        &self,
        h: &Harness,
        store: &rss_projection_postgres::PgStore,
        start: GenerationStart,
        control: &Control<'_, rt::Clock>,
    ) -> Result<Worker> {
        let definition = rss_mdm_inventory_postgres::definition();
        store
            .initialize(&self.scope, &definition, start, ReplayBound::Live, control)
            .await?;
        Ok(store.projection(
            store.takeover(&self.scope, &definition, control).await?,
            rss_mdm_inventory_postgres::Inventory::new(self.source.clone(), h.c.execution()),
        )?)
    }
}
fn limit() -> Result<RunLimit> {
    Ok(RunLimit::new(BatchLimit::new(8)?, 8)?)
}

async fn progress(c: &Context) -> Result<(Option<i64>, i64, i64)> {
    Ok(sqlx::query_as("SELECT position,(SELECT count(*) FROM rss_projection.receipts WHERE tenant_id=$1::uuid AND projection_id='inventory'),(SELECT count(*) FROM mdm.inventory WHERE tenant_id=$1::uuid) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND projection_id='inventory'")
        .bind(c.tenant.to_string()).fetch_one(&c.operator).await?)
}
async fn business(c: &Context, after: i64) -> Result<(Vec<Value>, i64)> {
    let rows: (Value,i64) = sqlx::query_as("SELECT coalesce(jsonb_agg(h.document ORDER BY h.revision),'[]'::jsonb),count(DISTINCT c.writer_xid) FROM mdm.inventory_history h JOIN mdm.asset_changes c USING(tenant_id,revision) WHERE h.tenant_id=$1::uuid AND h.revision>$2 AND h.document IS NOT NULL")
        .bind(c.tenant.to_string()).bind(after).fetch_one(&c.operator).await?;
    Ok((serde_json::from_value(rows.0)?, rows.1))
}
async fn reset(h: &Harness) -> Result<i64> {
    let mut tx = command::seed_transaction(&h.c).await?;
    for sql in [
        "DELETE FROM mdm.inventory WHERE tenant_id=$1::uuid",
        "DELETE FROM rss_projection.receipts WHERE tenant_id=$1::uuid AND projection_id='inventory'",
        "DELETE FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND projection_id='inventory'",
    ] {
        sqlx::query(sql)
            .bind(h.c.tenant.to_string())
            .execute(&mut *tx)
            .await?;
    }
    let revision = sqlx::query_scalar(
        "SELECT coalesce(max(revision),0) FROM mdm.asset_changes WHERE tenant_id=$1::uuid",
    )
    .bind(h.c.tenant.to_string())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(revision)
}

async fn counters(pool: &PgPool) -> Result<BTreeMap<&'static str, i64>> {
    let mut totals = BTreeMap::new();
    for (sql, n) in sqlx::query_as::<_, (String, i64)>(
        "SELECT statement, custom_plans+generic_plans FROM pg_prepared_statements",
    )
    .fetch_all(pool)
    .await?
    {
        let group = if sql.contains("rss_observation.journals") {
            "source"
        } else if sql.contains("rss_observation.batches") {
            "resolver"
        } else if sql.contains("rss_projection.") {
            "projection"
        } else if sql.contains("mdm.")
            || sql.contains("rss_transactional_messaging.check_execution()")
            || sql.contains("'rss.storage_target'")
        {
            "business"
        } else {
            continue;
        };
        *totals.entry(group).or_default() += n;
    }
    Ok(totals)
}

#[tokio::test]
#[ignore = "T2: the same sealed report page commits in order, rolls back and survives lost settlement"]
async fn report_page_settlement_and_cost() -> Result<()> {
    let h = Harness::open_in("inventory_capacity").await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(h.c.inputs.options(&h.c.profile, "mdm_runtime")?)
        .await?;
    let installed:(String,String,bool)=sqlx::query_as("SELECT obj_description('rss_observation'::regnamespace,'pg_namespace'),obj_description('rss_projection'::regnamespace,'pg_namespace'),has_function_privilege(current_user,'rss_observation.reclaim(text,bigint,bigint,numeric,integer)','EXECUTE')").fetch_one(&pool).await?;
    assert_eq!(
        installed,
        (
            "rss-observation-postgres:4".into(),
            "rss-projection-postgres:4".into(),
            false
        )
    );
    let page = Page::prepare(&h, &pool).await?;
    let stop = CancellationToken::new();
    let control = page.control(&stop);
    let store = rss_projection_postgres::PgStore::new(pool.clone(), &control).await?;
    let mut reference = None;
    for batched in [false, true] {
        let after = reset(&h).await?;
        let worker = page
            .worker(&h, &store, GenerationStart::beginning(), &control)
            .await?;
        let before = counters(&pool).await?;
        let run = if batched {
            rss_projection::run_batched(&*page.source, &worker, &control, limit()?).await
        } else {
            rss_projection::run(&*page.source, &worker, &control, limit()?).await
        };
        assert_eq!(run.into_result()?.applied, 3);
        let mut counts = counters(&pool).await?;
        for (group, count) in &mut counts {
            *count -= before.get(group).copied().unwrap_or(0);
        }
        for group in ["source", "resolver", "projection", "business"] {
            assert!(counts[group] > 0);
        }
        assert_eq!(counts["resolver"], 3);
        let (rows, xids) = business(&h.c, after).await?;
        let ids = rows
            .iter()
            .map(|v| v["batch_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, [0, 2, 3].map(|i| page.reports[i].id().as_str()));
        assert_eq!(progress(&h.c).await?, (Some(3), 3, 1));
        assert_eq!(xids, if batched { 1 } else { 3 });
        eprintln!(
            "inventory_product_cost batched={batched} applicable=3 xids={xids} statements={counts:?}"
        );
        if let Some(expected) = reference.take() {
            assert_eq!(rows, expected);
        } else {
            reference = Some(rows);
        }
    }
    settlement::exercise(&h, &page, &store).await?;
    let baseline = history::exercise(&h, &page, &store).await?;
    let tenant = h.c.tenant;
    pool.close().await;
    h.close().await?;
    history::restore(tenant, &page, baseline).await
}
