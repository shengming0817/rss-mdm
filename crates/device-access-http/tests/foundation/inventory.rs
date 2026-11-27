//! Replay the production DA host's accepted reports in a disposable copy of its database.
use super::*;
use anyhow::{Context as _, ensure};
use rss_mdm_device_access_postgres::reports::inventory::{Admission, MIN_PAGE_BYTES};
use rss_observation::{
    Access, Authority, LifecycleGrant, LookupOutcome, ObservationStore as _, ReadGrant,
};
use rss_projection::{Control, GenerationStart, Position, ProjectionScope, ReplayBound, RunLimit};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
struct Clock(std::time::Instant);
impl rss_observation::Clock for Clock {
    fn now(&self) -> std::time::Instant {
        rss_request_context::Clock::now(&context::Timer)
    }
}
impl rss_projection::Timer for Clock {
    fn now(&self) -> Duration {
        rss_observation::Clock::now(self).saturating_duration_since(self.0)
    }
    async fn sleep_until(&self, deadline: Duration) {
        tokio::time::sleep_until((self.0 + deadline).into()).await;
    }
}
struct Scoped(rss_observation::Scope);
impl Authority for Scoped {
    fn authorize(&self, r: Access<'_>) -> std::result::Result<(), rss_observation::Error> {
        if matches!(r,Access::Activate{scope}|Access::Read{scope} if scope==&self.0) {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
pub async fn verify(c: &Context) -> Result<()> {
    let options = c.inputs.database("postgres").options()?;
    let database = options.get_database().context("fixture database")?;
    let source = Uuid::parse_str(
        database
            .strip_prefix("t2_")
            .context("disposable T2 database required")?,
    )?
    .simple();
    let name = format!("t2_inventory_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().database("postgres"))
        .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE {name} TEMPLATE t2_{source}"
    )))
    .execute(&admin)
    .await?;
    let result = exercise(c, &name).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {name} WITH (FORCE)"
    )))
    .execute(&admin)
    .await?;
    admin.close().await;
    result
}
async fn reset(pool: &PgPool, tenant: Uuid) -> Result<()> {
    let mut tx = pool.begin().await?;
    for sql in [
        "DELETE FROM rss_da.inventory_assets WHERE tenant_id=$1",
        "DELETE FROM rss_projection.receipts WHERE tenant_id=$1 AND projection_id='da-inventory'",
        "DELETE FROM rss_projection.checkpoints WHERE tenant_id=$1 AND projection_id='da-inventory'",
    ] {
        sqlx::query(sql).bind(tenant).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn counts(pool: &PgPool) -> Result<BTreeMap<&'static str, i64>> {
    let mut result = BTreeMap::new();
    for (sql, n) in sqlx::query_as::<_, (String, i64)>(
        "SELECT statement,custom_plans+generic_plans FROM pg_prepared_statements",
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
        } else if sql.contains("rss_da.inventory_assets")
            || sql.contains("rss.storage_target")
            || sql.contains("check_execution()")
        {
            "business"
        } else {
            continue;
        };
        *result.entry(group).or_default() += n;
    }
    Ok(result)
}
async fn exercise(c: &Context, name: &str) -> Result<()> {
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let install = Uuid::parse_str(&c.inputs.installation.instance_id)?;
    let admin = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(c.inputs.database("postgres").options()?.database(name))
        .await?;
    let db = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            c.inputs
                .database("da_report_projection")
                .options()?
                .database(name),
        )
        .await?;
    let clock = Clock(rss_request_context::Clock::now(&context::Timer));
    let deadline = || {
        rss_request_context::Deadline::at(
            rss_observation::Clock::now(&clock) + Duration::from_secs(30),
        )
    };
    let open = || async {
        Admission::check(
            db.clone(),
            install,
            c.execution(),
            MIN_PAGE_BYTES,
            deadline(),
            Arc::new(context::Timer),
        )
        .await?
        .start(deadline())
        .await
    };
    let stop = CancellationToken::new();
    let limit = RunLimit::new(
        rss_projection::PageBudget::new(3, rss_projection::Event::MAX_PAYLOAD_BYTES)?,
        3,
    )?;
    let snapshot = || {
        sqlx::query_scalar::<_,serde_json::Value>("SELECT jsonb_agg(to_jsonb(a) ORDER BY device,registration_epoch,kind) FROM rss_da.inventory_assets a WHERE tenant_id=$1").bind(tenant).fetch_one(&admin)
    };
    let expected_assets = snapshot().await?;
    let expected:i64=sqlx::query_scalar("SELECT max(position) FROM rss_projection.checkpoints WHERE tenant_id=$1 AND projection_id='da-inventory'").bind(tenant).fetch_one(&admin).await?;
    ensure!(expected > 3);
    reset(&admin, tenant).await?;
    sqlx::raw_sql("CREATE TABLE public.observed_asset_writes(pos bigint, writer xid8); CREATE FUNCTION public.observe_asset() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN INSERT INTO public.observed_asset_writes VALUES(NEW.position,pg_current_xact_id()); RETURN NEW; END $$; CREATE TRIGGER observe_asset AFTER INSERT OR UPDATE ON rss_da.inventory_assets FOR EACH ROW EXECUTE FUNCTION public.observe_asset()").execute(&admin).await?;
    let worker = open().await?;
    let before = counts(&db).await?;
    ensure!(worker.project(&stop, limit).await.into_result()?.applied == 3);
    let mut cost = counts(&db).await?;
    for (g, n) in &mut cost {
        *n -= before.get(g).copied().unwrap_or_default();
    }
    let measured:(Vec<i64>,i64)=sqlx::query_as("SELECT array_agg(pos ORDER BY pos),count(DISTINCT writer) FROM public.observed_asset_writes").fetch_one(&admin).await?;
    ensure!(measured == (vec![1, 2, 3], 1) && cost.get("resolver") == Some(&3));
    eprintln!(
        "da_inventory_product_cost applicable=3 xids={} statements={cost:?}",
        measured.1
    );
    let scope = ProjectionScope::new(
        rss_projection::SourceScope::new(c.tenant, "da.observation.v1")?,
        "da-inventory",
        "da-report-assets-v1",
    )?;
    let receipts=sqlx::query_as::<_,(i64,String,Vec<u8>)>("SELECT b.log_position,r.event_id,r.fingerprint FROM rss_projection.receipts r JOIN rss_observation.batches b ON b.tenant_id=r.tenant_id AND encode(b.fingerprint,'hex')=r.event_id WHERE r.tenant_id=$1 AND r.projection_id='da-inventory' ORDER BY b.log_position").bind(tenant).fetch_all(&admin).await?;
    ensure!(receipts.len() == 3);
    let prefix = receipts
        .into_iter()
        .map(|(p, id, d)| {
            Ok(rss_projection::BaselineReceipt::new(
                scope.source().clone(),
                Position::new(p as u64)?,
                id,
                d.try_into()
                    .map_err(|_| anyhow::anyhow!("receipt fingerprint"))?,
            )?)
        })
        .collect::<Result<Vec<_>>>()?;
    sqlx::raw_sql("CREATE TABLE public.asset_baseline AS TABLE rss_da.inventory_assets; DROP TRIGGER observe_asset ON rss_da.inventory_assets; TRUNCATE public.observed_asset_writes; CREATE FUNCTION public.gate_asset() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(3318,1); RETURN NEW; END $$; CREATE TRIGGER gate_asset AFTER INSERT OR UPDATE ON rss_da.inventory_assets FOR EACH ROW WHEN(NEW.position=1) EXECUTE FUNCTION public.gate_asset()").execute(&admin).await?;
    drop(worker);
    reset(&admin, tenant).await?;
    let worker = open().await?;
    let mut gate = admin.begin().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM pg_advisory_xact_lock(3318,1)")
        .fetch_one(&mut *gate)
        .await?;
    let (report, expired) = tokio::join!(worker.project(&stop, limit), async {
        tokio::time::timeout(Duration::from_secs(6),async{
            loop{
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='da_report_projection' AND $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(&admin).await?;
                if blocked{return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        let row:(String,String)=sqlx::query_as("SELECT scope,batch_id FROM rss_observation.batches WHERE tenant_id=$1 AND log_position=2").bind(tenant).fetch_one(&admin).await?;
        let old: rss_observation::Scope = serde_json::from_str(&row.0)?;
        let new = rss_observation::Scope::new(
            c.tenant,
            old.object().clone(),
            old.registration().clone(),
            old.source().clone(),
            old.dataset().clone(),
            rss_observation::Epoch::new(Uuid::new_v4().to_string())?,
        );
        let other = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(
                c.inputs
                    .database("da_report_projection")
                    .options()?
                    .database(name),
            )
            .await?;
        let observation =
            rss_observation_postgres::PgStore::new(other.clone(), clock, deadline()).await?;
        let revision:i64=sqlx::query_scalar("SELECT revision::bigint FROM rss_observation.objects WHERE tenant_id=$1 AND object_id=$2").bind(tenant).bind(old.object().as_str()).fetch_one(&admin).await?;
        observation
            .activate(
                &LifecycleGrant::verify(&Scoped(new.clone()), new)?,
                Some(revision as u64),
                &rss_observation::Policy::new(86400, 3600, 3600)?,
                deadline(),
            )
            .await?;
        sqlx::query("UPDATE rss_observation.batches SET received_at=received_at-90001 WHERE tenant_id=$1 AND log_position=2").bind(tenant).execute(&admin).await?;
        let maint = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(
                c.inputs
                    .database("da_report_projection")
                    .options()?
                    .username("da_observation_maintenance")
                    .database(name),
            )
            .await?;
        let mut tx = maint.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let n:i32=sqlx::query_scalar("SELECT reclaimed FROM rss_observation.reclaim($1,floor(extract(epoch FROM clock_timestamp()))::bigint,2,NULL,1024)").bind(&row.0).fetch_one(&mut *tx).await?;
        ensure!(n == 1);
        tx.commit().await?;
        gate.rollback().await?;
        ensure!(matches!(
            observation
                .lookup(
                    &ReadGrant::verify(&Scoped(old.clone()), old)?,
                    &rss_observation::Id::new(row.1)?,
                    deadline()
                )
                .await?,
            LookupOutcome::Expired
        ));
        other.close().await;
        maint.close().await;
        Ok::<_, anyhow::Error>(())
    });
    expired?;
    let err = report
        .into_result()
        .err()
        .context("released page committed")?;
    ensure!(
        err.kind() == rss_projection::ErrorKind::HistoryExpired
            && err.diagnostic().and_then(|d| d.position()) == Some(Position::new(2)?)
    );
    let empty:(Option<i64>,i64,i64)=sqlx::query_as("SELECT position,(SELECT count(*) FROM rss_da.inventory_assets WHERE tenant_id=$1),(SELECT count(*) FROM rss_projection.receipts WHERE tenant_id=$1 AND projection_id='da-inventory') FROM rss_projection.checkpoints WHERE tenant_id=$1 AND projection_id='da-inventory'").bind(tenant).fetch_one(&admin).await?;
    ensure!(empty == (None, 0, 0));
    drop(worker);
    ensure!(matches!(
        open().await,
        Err(rss_mdm_device_access_postgres::Error::Conflict)
    ));
    reset(&admin, tenant).await?;
    sqlx::raw_sql("DROP TRIGGER gate_asset ON rss_da.inventory_assets; INSERT INTO rss_da.inventory_assets SELECT * FROM public.asset_baseline").execute(&admin).await?;
    let control = Control::new(
        &clock,
        rss_projection::Timer::now(&clock) + Duration::from_secs(30),
        &stop,
    );
    let pg = rss_projection_postgres::PgStore::new(db.clone(), &control).await?;
    let definition = rss_projection::DefinitionIdentity::new(
        sha2::Sha256::digest(rss_mdm_device_access_postgres::reports::inventory::INSTALL_SQL)
            .into(),
    );
    pg.initialize(
        &scope,
        &definition,
        GenerationStart::after(Position::new(3)?, prefix)?,
        ReplayBound::Live,
        &control,
    )
    .await?;
    let worker = open().await?;
    let result = worker
        .project(
            &stop,
            RunLimit::new(
                rss_projection::PageBudget::new(64, rss_projection::Event::MAX_PAYLOAD_BYTES)?,
                1024,
            )?,
        )
        .await
        .into_result()?;
    ensure!(
        result.position == Some(Position::new(expected as u64)?)
            && result.applied == expected as u64 - 3
    );
    ensure!(snapshot().await? == expected_assets);
    ensure!(
        open()
            .await?
            .project(&stop, limit)
            .await
            .into_result()?
            .applied
            == 0
    );
    db.close().await;
    admin.close().await;
    Ok(())
}
use sha2::Digest;
