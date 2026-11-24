//! Tenant-aware admission to the physical PostgreSQL scheduling pool.
use crate::capacity::{Capacity, Slot};
use rss_reconcile::{
    ClaimBatch, Completion, Control, DurableStore, Error, ErrorKind, ResourceSet, Scope, Target,
    Timer,
};
use rss_reconcile_postgres::{CloseOutcome, PgClaim, PgOperationError, PgStore, PgTransaction};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

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
        let _slot = self.connection(scope, control).await?;
        self.store
            .claim_due(scope, limit, scan_budget, lease, control)
            .await
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
        self.store.finish(claim, completion, control).await
    }
    async fn release<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let _slot = self.connection(claim.target().scope(), control).await?;
        self.store.release(claim, control).await
    }
}
