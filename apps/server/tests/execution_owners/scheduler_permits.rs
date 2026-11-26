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

#[tokio::test]
#[ignore = "T2: startup cancellation drains the pool registered before the scheduler probe"]
async fn interrupted_startup_drains_the_probing_pool() -> Result<()> {
    use rss_runtime::ManagedResource;
    let inputs = Inputs::load()?;
    let operator = inputs.pool("shared", "postgres").await?;
    let name = format!("scheduler-startup-{}", Uuid::new_v4());
    let options = inputs
        .options("shared", "mdm_scheduler_runtime")?
        .application_name(&name);
    let (send, mut receive) = tokio::sync::oneshot::channel();
    let mut opening = Box::pin(crate::scheduler::SchedulerStorage::open(
        "command-scheduler-postgres",
        options,
        |resource| {
            assert!(send.send(resource).is_ok());
        },
    ));
    let resource = tokio::select! {
        biased;
        registered = &mut receive => registered?,
        _ = &mut opening => anyhow::bail!("scheduler probe completed before the host could cancel"),
    };
    let connected = || {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1)")
            .bind(&name).fetch_one(&operator)
    };
    ensure!(
        connected().await?,
        "expected the probing backend to be present"
    );
    drop(opening);
    resource.shutdown().await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !connected().await? {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}

#[derive(Default)]
struct HeldObservation {
    entered: CancellationToken,
    resume: CancellationToken,
}

impl rss_reconcile::Reconciler<PgClaim> for HeldObservation {
    type State = ();
    async fn observe<T: rss_reconcile::Timer>(
        &self,
        _: &PgClaim,
        _: &Control<'_, T>,
    ) -> Result<rss_reconcile::ReconcileStep<rss_reconcile::ReconcileDiff<()>>, rss_reconcile::Error>
    {
        self.entered.cancel();
        self.resume.cancelled().await;
        Ok(rss_reconcile::ReconcileStep::Ready(
            rss_reconcile::ReconcileDiff::between(
                rss_reconcile::DesiredState::present(()),
                rss_reconcile::ActualState::present(()),
            ),
        ))
    }
    async fn apply<T: rss_reconcile::Timer>(
        &self,
        _: &PgClaim,
        _: rss_reconcile::ReconcileDiff<()>,
        _: &Control<'_, T>,
    ) -> Result<rss_reconcile::ReconcileStep<()>, rss_reconcile::Error> {
        unreachable!("matching desired and actual state")
    }
}

#[tokio::test]
#[ignore = "T2: reserved claim hands off the DB slot independently of its running execution"]
async fn reserved_claim_holds_admission_until_return() -> Result<()> {
    use rss_mdm_work_page::{capacity::Capacity, reconcile};
    let clock = Timer::new();
    let stop = CancellationToken::new();
    let control = Budget::new(&clock, Duration::from_secs(20), &stop);
    let f = Fixture::open(&control).await?;
    let (a, b) = (f.target().await?, f.target().await?);
    let peer = f.claim(&b, &control).await?;
    let scope = a.scope().clone();
    let tenant = Uuid::from_bytes(scope.tenant().octets());
    f.scheduler
        .wake(&a, &ResourceSet::empty(scope.tenant()), &control)
        .await?;
    let (gate, blocker) = f.hold_next_return().await?;
    let observer = Arc::new(HeldObservation::default());
    let policy = super::policy()?;
    let execution = Capacity::new(std::num::NonZeroUsize::MIN);
    let notify = tokio::sync::Notify::new();
    let worker_stop = CancellationToken::new();
    let runner = reconcile::run(
        &execution,
        policy,
        &worker_stop,
        &notify,
        |after| std::future::ready(Ok(after.is_none().then_some(tenant).into_iter().collect())),
        {
            let (store, observer, done) =
                (f.scheduler.clone(), observer.clone(), worker_stop.clone());
            move |_, grant, stop| {
                let (store, observer, scope, done) =
                    (store.clone(), observer.clone(), scope.clone(), done.clone());
                async move {
                    let result = reconcile::batch(
                        (&store, &*observer),
                        grant,
                        &scope,
                        policy,
                        &stop,
                        |_| {},
                    )
                    .await;
                    done.cancel();
                    result
                }
            }
        },
    );
    let proof = async {
        tokio::time::timeout(Duration::from_secs(4), observer.entered.cancelled()).await?;
        let (returning, _) =
            wait_for_blocked_attempt(&f.operator, blocker, "pg_advisory_xact_lock").await?;
        ensure!(f.lease(&a).await?.1.is_some());
        queued_admission(&f.scheduler, a.scope(), &control, &clock).await?;
        f.scheduler
            .finish(&peer, Completion::Converged, &control)
            .await?;
        ensure!(f.lease(&b).await? == (peer.epoch(), None));
        ensure!(
            crate::authority_t2_support::blocked_attempt(
                &f.operator,
                blocker,
                "pg_advisory_xact_lock"
            )
            .await?
            .is_some_and(|(pid, _)| pid == returning)
        );
        gate.rollback().await?;
        // The handler still owns the only execution slot when A regains DB admission.
        f.backend(&a, &control).await?;
        observer.resume.cancel();
        anyhow::Ok(())
    };
    tokio::try_join!(async { anyhow::Ok(runner.await?) }, proof)?;
    ensure!(f.lease(&a).await?.1.is_none());
    ensure!(f.scheduler.close(&control).await == CloseOutcome::Drained);
    Ok(())
}
