//! Product ingress bridge. RSS owns durable wake, claims and transaction settlement.
//! ref: rss crates/reconcile-postgres/src/messaging.rs@ec67bd142d70cb8f0d56feae636ac9471e7471fc
use super::*;
use tokio_util::sync::CancellationToken;
mod dispatch;
mod groups;
pub mod jobs;
mod model;

mod scopes;
use crate::automation::{JobInput, TaskKind};
pub use model::{GroupStart, ScopeInput, SourceSet};

fn device_reference(id: &str) -> String {
    use sha2::Digest;
    format!("device.{:x}", sha2::Sha256::digest(id.as_bytes()))
}

pub struct Timer(tokio::time::Instant);
impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}
impl Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "monotonic clock injection boundary"
    )]
    pub fn new() -> Self {
        Self(tokio::time::Instant::now())
    }
}
impl rss_reconcile::Timer for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "monotonic clock injection boundary"
    )]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        match self.0.checked_add(at) {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    }
}
pub fn asset_target(tenant: TenantId) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.assets").expect("constant domain"),
        "changes",
    )
    .expect("constant entity")
}
impl Planning {
    /// A discovery read is only a hint. Wake and forwarding happen atomically;
    /// forwarded history stays until the business checkpoint consumes it.
    pub async fn forward_asset_changes(&self) -> std::result::Result<u64, Error> {
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let pending = self.runtime.local_tx(self.tenant, deadline(), |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT forwarded)")
                    .bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Ok, |_| Err(Error::Unavailable(Failure::PlanningStorage)), |_| Err(Error::Unavailable(Failure::PlanningStorage)), |_| Err(Error::CommitUnknown), |_| Err(Error::CommitUnknown), |_| Err(Error::Unavailable(Failure::PlanningStorage)))?;
        if !pending {
            return Ok(0);
        }
        self.runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (self, asset_target(self.tenant).clone(), ()),
                |(service, target, context), tx| {
                    Box::pin(async move {
                        service
                            .audit_store
                            .lock_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        rss_reconcile_postgres::messaging::wake_in(tx, target, context, |_, tx| {
                            Box::pin(async move {
                                let tenant = tx.tenant_id().to_string();
                                tx.with_connection(move |c| {
                                    Box::pin(async move {
                                        let result = sqlx::query(
                                            r#"
                      WITH batch AS (
                        SELECT revision FROM mdm.asset_changes
                        WHERE tenant_id=$1::uuid AND NOT forwarded ORDER BY revision
                        LIMIT 1000 FOR UPDATE SKIP LOCKED
                      ) UPDATE mdm.asset_changes c SET forwarded=true FROM batch b
                        WHERE c.tenant_id=$1::uuid AND c.revision=b.revision
                    "#,
                                        )
                                        .bind(tenant)
                                        .execute(&mut *c)
                                        .await?;
                                        if result.rows_affected() > 0 {
                                            crate::worker_wake::notify(
                                                c,
                                                crate::worker_wake::Work::Automation,
                                            )
                                            .await?;
                                        }
                                        Ok(result.rows_affected())
                                    })
                                })
                                .await
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::PlanningStorage)),
                |_| Err(Error::Unavailable(Failure::PlanningStorage)),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::PlanningStorage)),
            )
    }
}

mod health;
pub use health::{BridgeObservation, BridgeOutcome, HealthFailure, IngressHealth};
