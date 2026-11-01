//! Exact union of privileges required by the shared host transaction role.
use rss_transactional_messaging_postgres::PgTransaction;
fn contract() -> String {
    let mut sql = include_str!("command-admission.sql").to_owned();
    sql = sql.replace(
        "{agent_update_columns}",
        rss_mdm_agent_channel::UPDATE_COLUMNS,
    );
    sql = sql.replace(
        "{agent_allowed_tables}",
        rss_mdm_agent_channel::ALLOWED_TABLES,
    );
    sql = sql.replace(
        "{windows_update_columns}",
        rss_mdm_windows_channel::UPDATE_COLUMNS,
    );
    sql = sql.replace(
        "{windows_allowed_tables}",
        rss_mdm_windows_channel::ALLOWED_TABLES,
    );
    sql = sql.replace(
        "{apple_update_columns}",
        rss_mdm_apple_channel::UPDATE_COLUMNS,
    );
    sql = sql.replace(
        "{apple_allowed_tables}",
        rss_mdm_apple_channel::ALLOWED_TABLES,
    );
    sql
}
pub(super) async fn admit(
    tx: &mut PgTransaction<'_>,
) -> std::result::Result<(), rss_transactional_messaging_postgres::PgError> {
    tx.with_connection(|c| Box::pin(rss_mdm_execution_service::source_changes::verify_storage(c)))
        .await?;
    tx.with_connection(|c| {
        Box::pin(async move {
            rss_mdm_agent_channel::verify_delivery(c).await?;
            rss_mdm_script_service::verify_storage(c).await?;
            rss_mdm_registration_service::device_access::execution::verify_storage(c).await?;
            rss_mdm_recovery_credentials::verify_storage(c).await?;
            rss_mdm_inventory_service::collection::execution::verify_storage(c).await?;
            rss_mdm_windows_channel::verify_delivery(c).await?;
            rss_mdm_inventory_postgres::verify_asset_history(c).await?;
            rss_mdm_execution_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command authority admission: {e}"))?;
            rss_mdm_authorization_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command authorization admission: {e}"))?;
            rss_mdm_registration_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command registration admission: {e}"))?;
            rss_mdm_device_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command device admission: {e}"))?;
            rss_mdm_inventory_postgres::verify_collections(c)
                .await
                .map_err(|_| sqlx::Error::Protocol("collection execution admission".into()))
        })
    })
    .await?;
    let (allowed, rejected_sources) = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_as::<_, (bool, Option<String>)>(sqlx::AssertSqlSafe(contract()))
                    .fetch_one(c)
                    .await
                    .inspect_err(|e| eprintln!("command catalog admission: {e}"))
            })
        })
        .await?;
    if !allowed {
        eprintln!(
            "command admission: runtime authority rejected; tenant isolation sources: {}",
            rejected_sources.as_deref().unwrap_or("valid")
        );
        return Err(sqlx::Error::Protocol("host storage admission rejected".into()).into());
    }
    Ok(())
}

use crate::Error;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime};
use std::{sync::Arc, time::Duration};
/// Admit the shared host resources; business owners bind only their required capabilities.
pub(crate) async fn open(
    runtime: Arc<PgRuntime>,
    options: sqlx::postgres::PgConnectOptions,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
    command_clock: rss_device_command_postgres::CommandClock,
    domain: rss_transactional_messaging::message::MessagingDomain,
) -> Result<
    (
        Arc<PgOutboxStore<()>>,
        rss_device_command_postgres::PgStore<()>,
        rss_reconcile_postgres::PgStore,
        sqlx::PgPool,
    ),
    Error,
> {
    let bad = || Error::Configuration(crate::ConfigIssue::Execution);
    bind_native_key(&runtime, tenant, protection.fingerprint_id()).await?;
    let caller = runtime.clone();
    let (outbox, store) = runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        rss_mdm_policy_postgres::verify_authority(c).await?;
                        rss_mdm_scope_postgres::verify_authority(c).await?;
                        rss_mdm_inventory_service::verify_authority(c).await?;
                        rss_mdm_agent_channel::signature_retirement::verify_authority(c).await?;
                        rss_mdm_apple_channel::verify_authority(c).await
                    })
                })
                .await?;
                admit(tx).await.map_err(|_| {
                    PgError::from(sqlx::Error::Protocol("command admission".into()))
                })?;
                bind_command_in(caller, tx, command_clock, domain)
                    .await
                    .inspect_err(|_| eprintln!("command startup: device-command admission failed"))
            })
        })
        .await
        .fold(
            Ok,
            |_| {
                eprintln!("command startup: transaction failed");
                Err(bad())
            },
            |_| {
                eprintln!("command startup: transaction failed");
                Err(bad())
            },
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |_| {
                eprintln!("command startup: transaction failed");
                Err(bad())
            },
        )?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(crate::background::SCHEDULER_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .map_err(|_| bad())?;
    let timer = Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let reconcile = match rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("command startup: reconcile admission failed");
            pool.close().await;
            return Err(bad());
        }
    };
    Ok((outbox, store, reconcile, pool))
}

pub async fn bind_command_in(
    runtime: Arc<PgRuntime>,
    tx: &mut PgTransaction<'_>,
    clock: rss_device_command_postgres::CommandClock,
    domain: rss_transactional_messaging::message::MessagingDomain,
) -> std::result::Result<
    (
        Arc<PgOutboxStore<()>>,
        rss_device_command_postgres::PgStore<()>,
    ),
    PgError,
> {
    runtime.validate_transaction(tx)?;
    let budget = rss_transactional_messaging::policy::DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(6),
        Duration::from_secs(6),
        Duration::from_secs(6),
    )
    .map_err(|_| sqlx::Error::Protocol("command delivery budget".into()))?;
    let outbox = Arc::new(PgOutboxStore::new(runtime, domain, budget)?);
    let callers = rss_device_command_postgres::CallerRoles::new(&[
        "mdm_command_runtime",
        "mdm_policy_runtime",
    ])
    .map_err(|_| PgError::from(sqlx::Error::Protocol("command caller declaration".into())))?;
    let store =
        rss_device_command_postgres::PgStore::new(tx, outbox.clone(), clock, &callers).await?;
    Ok((outbox, store))
}

pub async fn bind_native_key(
    runtime: &PgRuntime,
    tenant: TenantId,
    key_id: &str,
) -> std::result::Result<(), Error> {
    let result = runtime
        .local_tx_with_context(tenant, deadline(), key_id, |key_id, tx| {
            Box::pin(async move { rss_mdm_native_protection::binding::bind_in(tx, key_id).await })
        })
        .await;
    result.fold(
        |_| Ok(()),
        |_| Err(Error::Unavailable(crate::Failure::CommandStorage)),
        |_| Err(Error::Unavailable(crate::Failure::CommandStorage)),
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(crate::Failure::CommandStorage)),
    )
}

fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6))
}
struct Timer(tokio::time::Instant);
impl Timer {
    #[allow(clippy::disallowed_methods, reason = "host monotonic clock boundary")]
    fn new() -> Self {
        Self(tokio::time::Instant::now())
    }
}
impl rss_reconcile::Timer for Timer {
    #[allow(clippy::disallowed_methods, reason = "host monotonic clock boundary")]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        match self.0.checked_add(at) {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    }
}
