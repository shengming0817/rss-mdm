//! Hold a real scheduler connection after commit while the peer tenant makes progress.
use crate::authority_t2_support::{Inputs, seed_tenant, wait_for_blocked_attempt};
use anyhow::{Result, ensure};
use rss_mdm_policy_service::clock::Timer;
use rss_mdm_work_page::scheduler::Scheduler;
use rss_reconcile::{Completion, Control, DurableStore, ErrorKind, ResourceSet, Scope, Target};
use rss_reconcile_postgres::{CloseOutcome, PgClaim, PgOperationError, PgTransaction};
use rss_request_context::TenantId;
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use std::{
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type Budget<'a> = Control<'a, Timer>;

struct Fixture {
    operator: PgPool,
    pool: PgPool,
    scheduler: Scheduler,
    next_return: Arc<AtomicI32>,
}

impl Fixture {
    async fn open(control: &Budget<'_>) -> Result<Self> {
        let inputs = Inputs::load()?;
        // One return blocker, one peer row lock, one independent observer.
        let operator = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(inputs.options("shared", "postgres")?)
            .await?;
        let next_return = Arc::new(AtomicI32::new(0));
        let armed = next_return.clone();
        let pool = PgPoolOptions::new()
            .min_connections(2)
            .max_connections(2)
            .after_release(move |conn, _| {
                let key = armed.swap(0, Ordering::SeqCst);
                Box::pin(async move {
                    if key != 0 {
                        sqlx::query("SELECT pg_advisory_xact_lock(3302,$1)")
                            .bind(key)
                            .execute(conn)
                            .await?;
                    }
                    Ok(true)
                })
            })
            .connect_with(inputs.options("shared", "mdm_scheduler_runtime")?)
            .await?;
        let scheduler = Scheduler::new(pool.clone(), control).await?;
        Ok(Self {
            operator,
            pool,
            scheduler,
            next_return,
        })
    }

    async fn target(&self) -> Result<Target> {
        let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
        seed_tenant(&self.operator, tenant).await?;
        Ok(Target::new(
            Scope::new(tenant, "mdm.permit-test")?,
            "same-entity",
        )?)
    }

    async fn claim(&self, target: &Target, control: &Budget<'_>) -> Result<PgClaim> {
        self.scheduler
            .wake(
                target,
                &ResourceSet::empty(target.scope().tenant()),
                control,
            )
            .await?;
        let mut batch = self
            .scheduler
            .claim_due(target.scope(), 1, 1, Duration::from_secs(30), control)
            .await?;
        let claim = batch.claims.pop().expect("one due target");
        ensure!(claim.target() == target);
        Ok(claim)
    }

    async fn hold_next_return(&self) -> Result<(Transaction<'_, Postgres>, i32)> {
        let mut lock = self.operator.begin().await?;
        let pid: i32 = sqlx::query_scalar(
            "SELECT pg_backend_pid(), pg_advisory_xact_lock(3302, pg_backend_pid())",
        )
        .fetch_one(&mut *lock)
        .await?;
        // Every earlier return (including the startup probe) has passed its hook.
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.pool.num_idle() != 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        self.next_return.store(pid, Ordering::SeqCst);
        Ok((lock, pid))
    }

    async fn lease(&self, target: &Target) -> Result<(i64, Option<i64>)> {
        Ok(sqlx::query_as("SELECT epoch,(extract(epoch FROM lease_until)*1000000)::bigint FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3")
            .bind(target.scope().tenant().to_string()).bind(target.scope().reconciler())
            .bind(target.entity()).fetch_one(&self.operator).await?)
    }

    async fn backend(&self, target: &Target, control: &Budget<'_>) -> Result<i32> {
        Ok(self
            .scheduler
            .local_tx(target.scope(), control, |tx| Box::pin(backend_pid(tx)))
            .await?)
    }
}

async fn backend_pid(tx: &mut PgTransaction<'_>) -> Result<i32, PgOperationError> {
    tx.with_connection(|conn| {
        Box::pin(sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(conn))
    })
    .await
}

fn unexpected_transaction<'a>(
    _: &'a mut PgTransaction<'_>,
) -> futures::future::BoxFuture<'a, Result<(), PgOperationError>> {
    panic!("transaction started without scheduler admission")
}

async fn queued_admission(
    store: &Scheduler,
    scope: &Scope,
    control: &Budget<'_>,
    clock: &Timer,
) -> Result<()> {
    let short = control.child(Duration::from_millis(150));
    ensure!(
        store
            .local_tx(scope, &short, unexpected_transaction)
            .await
            .unwrap_err()
            .kind()
            == ErrorKind::Deadline
    );
    let stop = CancellationToken::new();
    let cancel = Budget::new(clock, Duration::from_secs(2), &stop);
    let mut wait = Box::pin(store.local_tx(scope, &cancel, unexpected_transaction));
    ensure!(futures::poll!(&mut wait).is_pending());
    stop.cancel();
    ensure!(wait.await.unwrap_err().kind() == ErrorKind::Cancelled);
    Ok(())
}

#[tokio::test]
#[ignore = "T2: an acknowledged settlement retains tenant admission through physical return"]
async fn peer_renews_while_acknowledged_connection_returns() -> Result<()> {
    let clock = Timer::new();
    let stop = CancellationToken::new();
    let control = Budget::new(&clock, Duration::from_secs(30), &stop);
    let f = Fixture::open(&control).await?;
    let (a, b) = (f.target().await?, f.target().await?);
    let old = f.claim(&a, &control).await?;
    let peer = f.claim(&b, &control).await?;
    let (gate, blocker) = f.hold_next_return().await?;
    f.scheduler
        .finish(&old, Completion::Converged, &control)
        .await?;
    let (returning, _) =
        wait_for_blocked_attempt(&f.operator, blocker, "pg_advisory_xact_lock").await?;
    ensure!(f.lease(&a).await? == (old.epoch(), None));

    let before = f.lease(&b).await?.1.expect("active peer lease");
    let mut row = f.operator.begin().await?;
    let locked: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3 FOR UPDATE")
        .bind(b.scope().tenant().to_string()).bind(b.scope().reconciler()).bind(b.entity())
        .fetch_one(&mut *row).await?;
    let prove_peer = async {
        let (renewing, _) = wait_for_blocked_attempt(&f.operator, locked, "").await?;
        ensure!(renewing != returning);
        row.rollback().await?;
        Ok(())
    };
    // Leave the spare connection idle throughout A's admission check: an early
    // permit release would run its callback immediately on that connection.
    queued_admission(&f.scheduler, a.scope(), &control, &clock).await?;
    tokio::try_join!(prove_peer, async {
        Ok::<_, anyhow::Error>(
            f.scheduler
                .renew(&peer, Duration::from_secs(90), &control)
                .await?,
        )
    })?;
    let (epoch, renewed) = f.lease(&b).await?;
    ensure!(epoch == peer.epoch() && renewed.is_some_and(|after| after > before));
    ensure!(
        crate::authority_t2_support::blocked_attempt(&f.operator, blocker, "pg_advisory_xact_lock")
            .await?
            .is_some()
    );
    gate.rollback().await?;
    let current = f.claim(&a, &control).await?;
    ensure!(current.epoch() > old.epoch());
    let valid = f.lease(&a).await?;
    ensure!(
        f.scheduler
            .release(&old, &control)
            .await
            .unwrap_err()
            .kind()
            == ErrorKind::Fenced
    );
    ensure!(valid.0 == current.epoch() && valid.1.is_some() && f.lease(&a).await? == valid);
    f.scheduler
        .finish(&current, Completion::Converged, &control)
        .await?;
    ensure!(f.scheduler.close(&control).await == CloseOutcome::Drained);
    Ok(())
}

#[tokio::test]
#[ignore = "T2: cancellation, overdue return and interrupted drain retire the exact connection"]
async fn interrupted_and_overdue_connections_release_admission() -> Result<()> {
    let clock = Timer::new();
    let stop = CancellationToken::new();
    let control = Budget::new(&clock, Duration::from_secs(40), &stop);
    let f = Fixture::open(&control).await?;
    let a = f.target().await?;
    let spare = f.pool.acquire().await?;
    let cancel = CancellationToken::new();
    let interrupted = Budget::new(&clock, Duration::from_secs(10), &cancel);
    let (tx_pid, rx_pid) = tokio::sync::oneshot::channel();
    let work = f.scheduler.local_tx(a.scope(), &interrupted, |tx| {
        Box::pin(async move {
            let _ = tx_pid.send(backend_pid(tx).await?);
            std::future::pending::<Result<(), PgOperationError>>().await
        })
    });
    let (result, pid) = tokio::join!(work, async {
        let pid = rx_pid.await;
        cancel.cancel();
        pid
    });
    ensure!(result.unwrap_err().kind() == ErrorKind::CommitUnknown);
    ensure!(f.backend(&a, &control).await? != pid?);
    drop(spare);

    let (gate, blocker) = f.hold_next_return().await?;
    let retired = f.backend(&a, &control).await?;
    let held = wait_for_blocked_attempt(&f.operator, blocker, "pg_advisory_xact_lock").await?;
    ensure!(held.0 == retired);
    let healthy = f.pool.acquire().await?;
    let replacement = f
        .backend(&a, &control.child(Duration::from_secs(10)))
        .await?;
    ensure!(replacement != retired);
    gate.rollback().await?;
    drop(healthy);

    let (gate, blocker) = f.hold_next_return().await?;
    let returning = f.backend(&a, &control).await?;
    ensure!(
        wait_for_blocked_attempt(&f.operator, blocker, "pg_advisory_xact_lock")
            .await?
            .0
            == returning
    );
    ensure!(
        f.scheduler
            .close(&control.child(Duration::from_millis(100)))
            .await
            == CloseOutcome::Deadline
    );
    let peer = f.target().await?;
    let refused = f
        .scheduler
        .local_tx(peer.scope(), &control, unexpected_transaction)
        .await;
    ensure!(refused.unwrap_err().kind() == ErrorKind::Permanent);
    gate.rollback().await?;
    ensure!(f.scheduler.close(&control).await == CloseOutcome::Drained);
    Ok(())
}
