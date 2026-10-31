//! Individually fenced remaining-owner run recovery.
//! ref: RSS reconcile-postgres/src/messaging.rs@d0202b30379a067a94ef386e4c071b7f6cc3d47c;
//! Kubernetes sample-controller/controller.go (one queued object per reconciliation).
use crate::{Error, ExecutionService, Result, storage};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) enum Work {
    Run(Uuid),
}
impl Work {
    pub(crate) fn parse(entity: &str) -> Option<Self> {
        if let Some(id) = entity.strip_prefix("run:") {
            return Uuid::parse_str(id).ok().map(Self::Run);
        }
        None
    }
    fn entity(self) -> String {
        match self {
            Self::Run(id) => format!("run:{id}"),
        }
    }
}
async fn wake(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    work: Work,
) -> Result<()> {
    let target = rss_reconcile::Target::new(crate::recovery_scope(tx.tenant_id()), work.entity())
        .map_err(|_| Error::Malformed)?;
    reconcile
        .wake_in(
            tx,
            &target,
            &rss_reconcile::ResourceSet::empty(target.scope().tenant()),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    Ok(())
}
pub(crate) async fn wake_run(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    wake(reconcile, tx, Work::Run(id)).await
}
/// A durable run remains recoverable independently of notifications.
pub(crate) async fn active(tx: &mut PgTransaction<'_>, work: Work) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        match work {
            Work::Run(id) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2 AND state->>'execution' IN('not_started','running','unknown') AND state->>'cancellation'<>'confirmed')")
                .bind(tenant).bind(id).fetch_one(c).await,
        }
    })).await?)
}
/// A dispatched read waiting for its device has no mutation to perform. Recheck
/// current withdrawal/expiry without taking the exclusive endpoint execution slot.
pub(crate) async fn needs_step(
    _service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    work: Work,
) -> Result<bool> {
    if !active(tx, work).await? {
        return Ok(false);
    }
    Ok(true)
}
/// Foreground protocol requests keep their existing bounded device/channel wait.
pub(crate) async fn lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::device::store::lock_channel(
                c,
                &tenant,
                &device,
                rss_mdm_inventory::Channel::Mdm,
            )
            .await)
        })
    })
    .await??;
    Ok(())
}
/// Background claims yield a busy device to RSS instead of occupying a slot waiting.
pub(crate) async fn try_lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let selected = device.to_owned();
    let acquired = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(
                    rss_mdm_registration_service::lifecycle::try_lock_devices_in(
                        c,
                        &tenant,
                        &[selected],
                    )
                    .await,
                )
            })
        })
        .await??;
    if !acquired {
        return Ok(false);
    }
    lock_device(tx, device).await?;
    Ok(true)
}
pub(crate) async fn step(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    work: Work,
    _run_id: Uuid,
) -> Result<bool> {
    match work {
        Work::Run(id) => {
            super::recovery::recover_one(service, tx, id).await?;
            Ok(false)
        }
    }
}
