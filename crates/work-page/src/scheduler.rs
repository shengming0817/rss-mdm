//! Tenant-aware admission to the physical PostgreSQL scheduling pool.
use crate::capacity::{Capacity, Slot};
use rss_reconcile::{
    ClaimBatch, Completion, Control, DurableStore, Error, ErrorKind, ResourceSet, Scope, Target,
    Timer,
};
use rss_reconcile_postgres::{CloseOutcome, PgClaim, PgOperationError, PgStore, PgTransaction};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

// RSS and the owner's observation wrappers forward DurableStore::claim_due.
// Bind this reservation only while polling that exact claim call; renew and
// settlement never borrow another job's execution slots.
struct Reservation {
    slots: std::sync::Mutex<Vec<Slot>>,
    stop: CancellationToken,
}
tokio::task_local! { static CLAIM: Arc<Reservation>; }

pub(crate) async fn with_execution_slots<F: Future>(
    slots: Vec<Slot>,
    stop: CancellationToken,
    query: F,
) -> (F::Output, Vec<Slot>) {
    let reservation = Arc::new(Reservation {
        slots: std::sync::Mutex::new(slots),
        stop,
    });
    let result = CLAIM.scope(reservation.clone(), query).await;
    let slots = std::mem::take(&mut *reservation.slots.lock().expect("execution reservation"));
    (result, slots)
}

impl Reservation {
    // Preserve an immediately usable execution grant. When the database is busy,
    // requeue both requirements atomically, holding neither while waiting.
    async fn claim_connection(
        &self,
        db: &Arc<Capacity>,
        tenant: uuid::Uuid,
    ) -> Result<Option<(Slot, usize)>, Error> {
        let execution = std::mem::take(&mut *self.slots.lock().expect("execution reservation"));
        let (host, scope, window) = execution
            .first()
            .ok_or_else(|| Error::new(ErrorKind::Invariant))?
            .origin();
        if scope != tenant {
            return Err(Error::new(ErrorKind::Invariant));
        }
        let maximum = execution.len();
        if self.stop.is_cancelled() {
            return Ok(None);
        }
        let (execution, connection) = if let Some(connection) = db.try_connection(tenant) {
            (execution, Some(connection))
        } else {
            drop(execution);
            host.request(tenant, maximum, window, Some(db.clone()), &self.stop)
                .await
        };
        let width = execution.len();
        *self.slots.lock().expect("execution reservation") = execution;
        Ok(connection.map(|connection| (connection, width)))
    }
}

#[derive(Clone)]
pub struct Scheduler {
    store: PgStore,
    connections: Arc<Capacity>,
}

impl Scheduler {
    pub async fn new<T: Timer>(
        pool: sqlx::PgPool,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        let maximum = NonZeroUsize::new(pool.options().get_max_connections() as usize)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput))?;
        Ok(Self {
            store: PgStore::new(pool, control).await?,
            // A blocked tenant must leave a physical connection for peer settlements.
            connections: Capacity::with_tenant_limit(
                maximum,
                NonZeroUsize::new(maximum.get() - 1).unwrap_or(NonZeroUsize::MIN),
            ),
        })
    }

    /// Per-pool maximum read from the physical pool at registration.
    pub fn connection_limit(&self) -> NonZeroUsize {
        self.connections.limit()
    }

    async fn connection<T: Timer>(
        &self,
        scope: &Scope,
        control: &Control<'_, T>,
    ) -> Result<Slot, Error> {
        let tenant = uuid::Uuid::from_bytes(scope.tenant().octets());
        // The RSS control bounds the wait. Dropping admission removes its FIFO ticket.
        control
            .run(async {
                self.connections
                    .acquire(tenant, 1, &CancellationToken::new())
                    .await
                    .pop()
                    .ok_or_else(|| Error::new(ErrorKind::Invariant))
            })
            .await
    }

    pub async fn local_tx<T: Timer, R: Send, F>(
        &self,
        scope: &Scope,
        control: &Control<'_, T>,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut PgTransaction<'_>,
            )
                -> futures::future::BoxFuture<'c, Result<R, PgOperationError>>
            + Send,
    {
        let _slot = self.connection(scope, control).await?;
        self.store.local_tx(scope, control, operation).await
    }

    pub async fn close<T: Timer>(&self, control: &Control<'_, T>) -> CloseOutcome {
        self.store.close(control).await
    }
}

impl DurableStore for Scheduler {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let _slot = self.connection(target.scope(), control).await?;
        self.store.wake(target, resources, control).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let _slot = self.connection(target.scope(), control).await?;
        self.store.bind_resources(target, resources, control).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        scan_budget: u32,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<ClaimBatch<PgClaim>, Error> {
        let (_slot, limit) = if let Ok(reservation) = CLAIM.try_with(Arc::clone) {
            let grant = control
                .run(reservation.claim_connection(
                    &self.connections,
                    uuid::Uuid::from_bytes(scope.tenant().octets()),
                ))
                .await?;
            let Some((slot, granted)) = grant else {
                return Ok(ClaimBatch {
                    claims: Vec::new(),
                    more: false,
                });
            };
            (slot, limit.min(granted))
        } else {
            (self.connection(scope, control).await?, limit)
        };
        #[allow(
            clippy::disallowed_methods,
            reason = "physical claim start after connection admission"
        )]
        let started = tokio::time::Instant::now();
        let batch = self
            .store
            .claim_due(scope, limit, scan_budget, lease, control)
            .await?;
        crate::reconcile::scanned(
            scope,
            started,
            batch.more,
            batch.claims.iter().map(PgClaim::target),
        );
        Ok(batch)
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let _slot = self.connection(claim.target().scope(), control).await?;
        self.store.renew(claim, lease, control).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let _slot = self.connection(claim.target().scope(), control).await?;
        self.store.finish(claim, completion, control).await?;
        crate::reconcile::settled(claim.target(), Some(completion));
        Ok(())
    }
    async fn release<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let _slot = self.connection(claim.target().scope(), control).await?;
        self.store.release(claim, control).await?;
        crate::reconcile::settled(claim.target(), None);
        Ok(())
    }
}
