//! Count only queries issued by the measured future. Fixture and readback use separate scopes.
use super::*;
use rss_device_command::{BatchLimit, CommandId, ExactCommandIds, Scope, Store};
use rss_transactional_messaging::policy::OperationDeadline;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Counts {
    total: usize,
    exact: usize,
    point: usize,
}
#[derive(Clone, Default)]
struct Counter(Arc<std::sync::Mutex<Counts>>);

impl tracing::field::Visit for Counts {
    fn record_str(&mut self, field: &tracing::field::Field, sql: &str) {
        if field.name() == "db.statement" {
            self.exact += usize::from(sql.contains("WITH ORDINALITY AS requested(id, position)"));
            self.point += usize::from(sql.contains(
                "FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2",
            ));
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_str(field, &format!("{value:?}"));
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Counter {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "sqlx::query" {
            let mut counts = self.0.lock().unwrap();
            counts.total += 1;
            event.record(&mut *counts);
        }
    }
}
async fn measure<F: Future>(future: F) -> (F::Output, Counts) {
    let counter = Counter::default();
    let output = future
        .with_subscriber(tracing_subscriber::registry().with(counter.clone()))
        .await;
    let counts = *counter.0.lock().unwrap();
    (output, counts)
}

pub(super) async fn provider(h: &Harness, device: rss_mdm_agent_wire::DeviceId) -> Result<()> {
    let runtime = h.a.resources.storage.runtime.clone();
    let tenant = h.c.tenant;
    let command_device: Uuid = sqlx::query_scalar("SELECT command_device FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2")
        .bind(tenant.to_string()).bind(device.into_uuid()).fetch_one(&h.c.operator).await?;
    let scope = Scope::new(
        tenant,
        rss_device_command::DeviceId::parse(&command_device.to_string())?,
    );
    let ids = (1..=64)
        .map(|n| CommandId::parse(&Uuid::from_u128(n).to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let budget = OperationDeadline::from_remaining(Duration::from_secs(20));
    let attempt = runtime
        .clone()
        .local_tx(h.c.execution(), budget, move |tx| {
            Box::pin(async move {
                let (_, store) = crate::assembly::host_storage::bind_command_in(
                    runtime,
                    tx,
                    rss_device_command_postgres::CommandClock::Postgres,
                    BatchLimit::default(),
                    rss_mdm_device_service::control::messaging_domain(),
                )
                .await?;
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SAVEPOINT compare_page").execute(c).await?;
                        Ok(())
                    })
                })
                .await?;
                let (single, per_id) = measure(async {
                    let mut rows = Vec::new();
                    for id in &ids {
                        let page = ExactCommandIds::new(std::slice::from_ref(id)).expect("one id");
                        rows.extend(store.recover_exact(tx, scope, page).await?);
                    }
                    Ok::<_, rss_transactional_messaging_postgres::PgError>(rows)
                })
                .await;
                let single = single?;
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("ROLLBACK TO compare_page").execute(c).await?;
                        Ok(())
                    })
                })
                .await?;
                let (rows, batch) = measure(store.recover_exact(
                    tx,
                    scope,
                    ExactCommandIds::new(&ids).expect("distinct ids"),
                ))
                .await;
                let rows = rows?;
                assert_eq!(rows, single);
                assert_eq!(rows.iter().flatten().count(), ids.len());
                assert_eq!((per_id.exact, batch.exact, batch.point), (ids.len(), 1, 0));
                assert!(batch.total < per_id.total);
                eprintln!(
                    "exact recovery: ids={} singleton_sql={} page_sql={}",
                    ids.len(),
                    per_id.total,
                    batch.total
                );
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("ROLLBACK TO compare_page").execute(c).await?;
                        Ok(())
                    })
                })
                .await?;
                Ok(())
            })
        })
        .await;
    attempt.fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}

pub(super) async fn unknown_page(h: &Harness, device: &rss_mdm_agent_wire::DeviceId) -> Result<()> {
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let claim = claim_device(
        h,
        rss_mdm_device_service::control::recovery_scope(h.c.tenant),
        device,
        &control,
    )
    .await?;
    let ReconcileStep::Ready(diff) = h.a.service.observe(&claim, &control).await? else {
        anyhow::bail!("deferred observation")
    };
    h.a.resources.storage.runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    let (result, counts) = measure(control.run(h.a.service.apply(&claim, diff, &control))).await;
    assert_eq!(
        result.unwrap_err().kind(),
        rss_reconcile::ErrorKind::CommitUnknown
    );
    h.a.resources
        .storage
        .reconcile
        .release(&claim, &control)
        .await?;
    assert_eq!((counts.exact, counts.point), (1, 0));
    eprintln!(
        "product apply: 64 ids, 63 changed observations, sql={} exact={} settlement_point_reads={}",
        counts.total, counts.exact, counts.point
    );
    Ok(())
}
