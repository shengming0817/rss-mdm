//! Drive the installed product projector before asserting eventual audit history.
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
struct Timer;
impl Clock for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "real monotonic provider for the installed projector fixture"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::time::sleep_until(deadline.instant().into()).await;
    }
}
pub async fn drain(
    tenant: TenantId,
    integrity: rss_audit_postgres::Integrity,
) -> anyhow::Result<()> {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    drain_in(tenant, integrity, &config).await
}
/// The isolated installation fixture supplies its actual database coordinates.
pub async fn drain_in(
    tenant: TenantId,
    integrity: rss_audit_postgres::Integrity,
    config: &serde_json::Value,
) -> anyhow::Result<()> {
    let port = config["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("fixture port"))? as u16;
    let database = config["database"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture database"))?;
    let ca = config["ca"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture CA"))?;
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(port)
        .database(database)
        .username("mdm_audit_worker")
        .password("audit-projection-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(ca);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let runtime = Arc::new(
        PgRuntime::connect_consumer(
            PgConfig::new(
                "localhost",
                port,
                database,
                "mdm_audit_worker",
                PgPassword::new("audit-projection-fixture"),
                PgPrivateCa::from_pem(std::fs::read(ca)?)?,
            ),
            Timer,
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16])?,
                vec![(tenant, Epoch::new(1)?)],
            )?,
        )
        .await?,
    );
    let result = async {
        let cancel = tokio_util::sync::CancellationToken::new();
        let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(20))?;
        let control = rss_audit_postgres::Control::new(&Timer, cutoff, cutoff, &cancel);
        let audit =
            Arc::new(rss_audit_postgres::PgAudit::new(pool.clone(), integrity, &control).await?);
        let projector = rss_mdm_audit_integration::AuditProjection::new(
            runtime.clone(),
            audit,
            vec![tenant],
            Arc::new(rss_mdm_native_protection::Protector::new(&[59; 32])?),
            DeliveryBudget::new(
                Duration::from_secs(60),
                Duration::from_secs(5),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )?,
            OperationDeadline::from_cutoff(cutoff, &Timer),
        )
        .await?;
        loop {
            anyhow::ensure!(
                !cutoff.is_expired(Timer.now()),
                "audit projection did not catch up"
            );
            let report = projector
                .project_batch(
                    NonZeroUsize::new(64).unwrap(),
                    OperationDeadline::from_cutoff(cutoff, &Timer),
                    Duration::from_secs(6),
                )
                .await?;
            for identity in &report.recoveries {
                projector.resolve(identity, OperationDeadline::from_cutoff(cutoff, &Timer)).await?;
            }
            if let Some(error) = report.failure { return Err(error.into()); }
            if report.projected == 0 && report.deferred == 0 {
                // Another installed worker may own a lease: no claimable row is not a drained source.
                let pending = tokio::time::timeout_at(cutoff.instant().into(), async {
                let mut tx = pool.begin().await?;
                sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                    .bind(tenant.to_string()).execute(&mut *tx).await?;
                let pending: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM mdm_audit.receipts WHERE tenant_id=$1::uuid AND projected_at IS NULL)",
                ).bind(tenant.to_string()).fetch_one(&mut *tx).await?;
                tx.rollback().await?;
                Ok::<bool, anyhow::Error>(pending)
                }).await??;
                if !pending { break; }
            }
            for identity in &report.recoveries {
                projector.resolve(identity, OperationDeadline::from_cutoff(cutoff, &Timer)).await?;
            }
            if let Some(error) = report.failure { return Err(error.into()); }
            if report.projected == 0 || report.deferred > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    runtime.close().await;
    pool.close().await;
    result
}
