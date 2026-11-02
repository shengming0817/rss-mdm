//! Exact union of privileges required by the shared host transaction role.
use rss_transactional_messaging_postgres::PgTransaction;
fn contract() -> String {
    let mut sql = include_str!("command-admission.sql").to_owned();
    sql = sql.replace(
        "{agent_update_columns}",
        rss_mdm_agent_channel::update_columns_sql(rss_mdm_install_support::StorageProfile::Mdm),
    );
    sql = sql.replace(
        "{agent_allowed_tables}",
        rss_mdm_agent_channel::allowed_tables_sql(rss_mdm_install_support::StorageProfile::Mdm),
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
    sql = sql.replace("{apple_read_columns}", rss_mdm_apple_channel::READ_COLUMNS);
    sql
}
pub(super) async fn admit(
    tx: &mut PgTransaction<'_>,
) -> std::result::Result<(), rss_transactional_messaging_postgres::PgError> {
    tx.with_connection(|c| {
        Box::pin(rss_mdm_device_service::control::source_changes::verify_storage(c))
    })
    .await?;
    tx.with_connection(|c| {
        Box::pin(async move {
            rss_mdm_agent_channel::verify_delivery(rss_mdm_install_support::StorageProfile::Mdm, c)
                .await?;
            rss_mdm_script_service::verify_storage(c).await?;
            rss_mdm_device_access_postgres::device_access::execution::verify_storage(c).await?;
            rss_mdm_recovery_credentials::verify_storage(c).await?;
            rss_mdm_inventory_service::collection::execution::verify_storage(c).await?;
            rss_mdm_windows_channel::verify_delivery(c).await?;
            rss_mdm_inventory_postgres::verify_asset_history(c).await?;
            rss_mdm_device_service::control::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command authority admission: {e}"))?;
            rss_mdm_authorization_service::verify_authority(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
            )
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
/// Shared physical command resources; no business service is retained here.
pub(crate) struct Storage {
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub tenant: TenantId,
    pub reconcile: rss_reconcile_postgres::PgStore,
    pub read_pool: sqlx::PgPool,
    pub worker_budget: Arc<tokio::sync::Semaphore>,
}
impl Storage {
    pub(crate) async fn open(
        config: &crate::config::Config,
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
        protection: &rss_mdm_native_protection::Protector,
        mut acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
    ) -> Result<Self, Error> {
        let bad = || Error::Configuration(crate::ConfigIssue::CommandStorage);
        let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| bad())?;
        let (pg, binding) = crate::identity::runtime_inputs(
            &config.command_database,
            &config.storage_binding.target,
            &config.storage_binding.lineage,
            &[(tenant, config.storage_binding.epoch)],
        )?;
        let runtime = Arc::new(
            PgRuntime::connect(
                pg.with_pool_limits(0, config.background.command_connections()),
                crate::lifecycle::RuntimeTimer,
                binding,
            )
            .await
            .map_err(|_| Error::Unavailable(crate::Failure::CommandStorage))?,
        );
        acquire(rss_runtime::DynManagedResource::new_box(
            crate::owner_storage::Resource::new(runtime.clone(), "command-runtime-postgres"),
        ));
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit = Arc::new(
            audit
                .on_runtime(runtime.clone(), tenant, &budget.control())
                .await?,
        );
        bind_native_key(&runtime, tenant, protection.fingerprint_id()).await?;
        runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            rss_mdm_policy_postgres::verify_authority(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                            )
                            .await?;
                            rss_mdm_scope_postgres::verify_authority(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                            )
                            .await?;
                            rss_mdm_inventory_service::verify_authority(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                            )
                            .await?;
                            rss_mdm_agent_channel::signature_retirement::verify_authority(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                            )
                            .await?;
                            rss_mdm_apple_channel::verify_authority(c).await
                        })
                    })
                    .await?;
                    admit(tx).await.map_err(|_| {
                        PgError::from(sqlx::Error::Protocol("command admission".into()))
                    })?;
                    Ok(())
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

        let read_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(crate::background::SCHEDULER_CONNECTIONS)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(config.command_database.options()?)
            .await
            .map_err(|_| bad())?;
        acquire(rss_runtime::DynManagedResource::new_box(ReadPool(
            read_pool.clone(),
        )));
        let timer = Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let reconcile = rss_reconcile_postgres::PgStore::new(read_pool.clone(), &control)
            .await
            .map_err(|_| bad())?;
        Ok(Self {
            runtime,
            audit,
            tenant,
            reconcile,
            read_pool,
            worker_budget: Arc::new(tokio::sync::Semaphore::new(
                config.background.device_concurrency,
            )),
        })
    }
}
struct ReadPool(sqlx::PgPool);
impl rss_runtime::ManagedResource for ReadPool {
    fn name(&self) -> &str {
        "command-scheduler-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
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
            Box::pin(async move {
                rss_mdm_native_protection::binding::bind_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    tx,
                    key_id,
                )
                .await
            })
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
