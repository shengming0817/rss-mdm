//! Observe actual SQLx executions with startup positive controls and persisted results.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
};

#[derive(Clone, Default)]
struct Counts {
    queries: Arc<AtomicUsize>,
    catalog: Arc<AtomicUsize>,
}
#[derive(Default)]
struct Statement {
    catalog: bool,
}
impl Visit for Statement {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "db.statement" | "summary") {
            let sql = format!("{value:?}");
            self.catalog |= [
                "pg_proc",
                "pg_class",
                "pg_attribute",
                "pg_roles",
                "pg_namespace",
                "pg_constraint",
            ]
            .iter()
            .any(|name| sql.contains(name));
        }
    }
}
impl<S: Subscriber> Layer<S> for Counts {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() == "sqlx::query" {
            let mut statement = Statement::default();
            event.record(&mut statement);
            self.queries.fetch_add(1, Ordering::Relaxed);
            if statement.catalog {
                self.catalog.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[tokio::test]
#[ignore = "MODULE=audit.integrity: startup and business SQL on isolated database"]
async fn startup_probes_leave_both_transaction_hot_paths() -> Result<()> {
    let pool = pool("mdm_access").await?;
    let tenant = crate::planning::test_support::tenant();
    let runtime = crate::planning::test_support::runtime_role(tenant, "mdm_flow_runtime").await;
    for wide in [false, true] {
        if wide {
            crate::planning::test_support::sql(
                "CREATE SCHEMA audit_cost_unrelated; DO $$ BEGIN FOR i IN 1..200 LOOP EXECUTE format('CREATE FUNCTION audit_cost_unrelated.f%s() RETURNS integer LANGUAGE sql AS %L', i, 'SELECT 1'); END LOOP; END $$",
            );
        }
        for ledger in [false, true] {
            let counts = Counts::default();
            let observer = tracing_subscriber::registry().with(counts.clone());
            exercise(&pool, &runtime, ledger, wide, &counts)
                .with_subscriber(observer)
                .await?;
        }
    }
    runtime.close().await;
    pool.close().await;
    Ok(())
}

async fn exercise(
    pool: &PgPool,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    ledger: bool,
    wide: bool,
    counts: &Counts,
) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(20))?;
    let control = Control::new(&timer, cutoff, cutoff, &cancel);
    let store = AuditStore::new(pool.clone(), integrity(ledger)?, &control).await?;
    let tenant = crate::planning::test_support::tenant();
    runtime
        .local_tx_with_context(
            tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_cutoff(cutoff, &timer),
            &store,
            |store, tx| Box::pin(async move { store.validate_in(tx).await.map_err(Into::into) }),
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    ensure!(
        counts.catalog.load(Ordering::Relaxed) >= if ledger { 6 } else { 4 },
        "startup observer must see all complete contracts on both actual owners"
    );
    let initial_records = bytes(pool, tenant).await?.len();
    counts.catalog.store(0, Ordering::Relaxed);
    counts.queries.store(0, Ordering::Relaxed);
    let request = RequestAudit::new(tenant.to_string(), "audit_sql_observation");
    for borrowed in [false, true] {
        let fact = Fact::business(
            &request,
            &format!("cost-{ledger}-{wide}-{borrowed}"),
            b"request",
            200,
            "success",
            None,
        )?;
        for replayed in [false, true] {
            if borrowed {
                runtime
                    .local_tx_with_context(
                        tenant,
                        rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                            cutoff, &timer,
                        ),
                        (&store, &fact),
                        |(store, fact), tx| {
                            Box::pin(async move {
                                store.lock_in(tx).await?;
                                store
                                    .append_in(tx, fact, replayed)
                                    .await
                                    .map_err(Into::into)
                            })
                        },
                    )
                    .await
                    .fold(Ok, Err, Err, Err, Err, Err)?;
            } else {
                ensure!(
                    state(
                        store
                            .write(tenant, &control, (&store, &fact), |(store, fact), tx| {
                                Box::pin(async move { store.append(tx, fact, replayed).await })
                            })
                            .await
                    ) == "committed"
                );
            }
        }
    }
    let persisted = bytes(pool, tenant).await?;
    ensure!(persisted.len() == initial_records + 2);
    ensure!(counts.queries.load(Ordering::Relaxed) > 0);
    ensure!(
        counts.catalog.load(Ordering::Relaxed) == 0,
        "business SQL must not inspect Audit/Ledger/receipts catalogs"
    );
    println!(
        "audit hot SQL: ledger={ledger} wide={wide} queries={} catalog=0 records={}",
        counts.queries.load(Ordering::Relaxed),
        persisted.len()
    );
    request.finalize(None);
    Ok(())
}
