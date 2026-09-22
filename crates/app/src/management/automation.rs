//! Product ingress bridge. RSS owns durable wake, claims and transaction settlement.
//! ref: rss crates/reconcile-postgres/src/messaging.rs@ec67bd142d70cb8f0d56feae636ac9471e7471fc
use super::*;
use tokio_util::sync::CancellationToken;
mod dispatch;
mod groups;
mod jobs;
mod model;
mod plans;
mod runtime;
mod scopes;
pub(in crate::management) use model::{JobInput, ScopeInput, SourceSet, TaskKind};
pub(crate) use runtime::{Automation, Resource};
fn device_reference(id: &str) -> String {
    use sha2::Digest;
    format!("device.{:x}", sha2::Sha256::digest(id.as_bytes()))
}

pub(super) struct Timer(tokio::time::Instant);
impl Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "monotonic clock injection boundary"
    )]
    pub(super) fn new() -> Self {
        Self(tokio::time::Instant::now())
    }
}
impl rss_reconcile::Timer for Timer {
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
fn asset_target(tenant: TenantId) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.assets").expect("constant domain"),
        "changes",
    )
    .expect("constant entity")
}
impl Management {
    /// A discovery read is only a hint. Wake and forwarding happen atomically;
    /// forwarded history stays until the business checkpoint consumes it.
    pub(super) async fn forward_asset_changes(&self) -> std::result::Result<u64, Error> {
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let pending = self.runtime.local_tx(self.tenant, deadline(), |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT forwarded)")
                    .bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Ok, |_| Err(Error::Unavailable(Failure::ManagementStorage)), |_| Err(Error::Unavailable(Failure::ManagementStorage)), |_| Err(Error::CommitUnknown), |_| Err(Error::CommitUnknown), |_| Err(Error::Unavailable(Failure::ManagementStorage)))?;
        if !pending {
            return Ok(0);
        }
        rss_reconcile_postgres::messaging::wake_with(
            &self.runtime,
            &asset_target(self.tenant),
            &control,
            (),
            |_, tx| {
                Box::pin(async move {
                    let tenant = tx.tenant_id().to_string();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query(
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
                            .execute(c)
                            .await
                            .map(|r| r.rows_affected())
                        })
                    })
                    .await
                })
            },
        )
        .await
        .fold(
            Ok,
            |_| Err(Error::Unavailable(Failure::ManagementStorage)),
            |_| Err(Error::Unavailable(Failure::ManagementStorage)),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::ManagementStorage)),
        )
    }
}
