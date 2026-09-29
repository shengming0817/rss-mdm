//! Host assembly of execution storage, recovery and content adapters.
use crate::execution::{ExecutionService, deadline, messaging_domain, recovery, storage};
use crate::{Error, Failure};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::DeliveryBudget,
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
use std::{sync::Arc, time::Duration};
pub(crate) async fn open(
    config: &crate::config::Config,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
) -> std::result::Result<Arc<ExecutionService>, Error> {
    let bad = || Error::Configuration(crate::ConfigIssue::Execution);
    let database = &config.execution.database;
    let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| bad())?;
    let binding = ExecutionBinding::new(
        StorageIdentity::new(config.flow.storage.target, config.flow.storage.lineage)
            .map_err(|_| bad())?,
        vec![(
            tenant,
            Epoch::new(config.flow.storage.epoch).map_err(|_| bad())?,
        )],
    )
    .map_err(|_| bad())?;
    let pg = PgConfig::new(
        &database.host,
        database.port,
        &database.name,
        &database.user,
        PgPassword::new(crate::config::secret(&database.password_file)?.as_str()),
        PgPrivateCa::from_pem(crate::config::read(&database.ca_file, 1024 * 1024, false)?.to_vec())
            .map_err(|_| bad())?,
    );
    let runtime = Arc::new(
        PgRuntime::connect(pg, crate::lifecycle::RuntimeTimer, binding)
            .await
            .map_err(|_| Error::Unavailable(Failure::CommandStorage))?,
    );
    let result = async {
        let content = config
            .content
            .as_ref()
            .map(|c| {
                rss_mdm_content_service::Store::open(
                    c,
                    &tenant.to_string(),
                    Arc::new(crate::lifecycle::RuntimeTimer),
                )
            })
            .transpose()?;
        crate::database::admit_audit_runtime(&runtime, &audit_store, tenant).await?;
        let outbox = Arc::new(
            PgOutboxStore::new(
                runtime.clone(),
                messaging_domain(),
                DeliveryBudget::new(
                    Duration::from_secs(60),
                    Duration::from_secs(6),
                    Duration::from_secs(6),
                    Duration::from_secs(6),
                )
                .map_err(|_| bad())?,
            )
            .map_err(|_| bad())?,
        );
        let copy = outbox.clone();
        let store = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    storage::admit(tx).await.map_err(|_| {
                        PgError::from(sqlx::Error::Protocol("command admission".into()))
                    })?;
                    rss_device_command_postgres::PgStore::new(tx, copy)
                        .await
                        .inspect_err(|_| {
                            eprintln!("command startup: device-command admission failed")
                        })
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
                |_| Err(Error::Service(rss_mdm_flow_service::Error::CommitUnknown)),
                |_| Err(Error::Service(rss_mdm_flow_service::Error::CommitUnknown)),
                |_| {
                    eprintln!("command startup: transaction failed");
                    Err(bad())
                },
            )?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(database.options()?)
            .await
            .map_err(|_| bad())?;
        let timer = recovery::Timer::new();
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
        Ok(Arc::new(ExecutionService {
            agent_store: Arc::new(rss_mdm_agent_channel::Bindings),
            apple_store: Arc::new(rss_mdm_apple_channel::flow_store::Store),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            audit_store,
            runtime: runtime.clone(),
            outbox,
            store,
            reconcile,
            tenant,
            instance: config.identity.instance_id.clone(),
            content,
            signer: config
                .task_signing
                .as_ref()
                .map(crate::task_signing::open)
                .transpose()?
                .map(Arc::new),
        }))
    }
    .await;
    if result.is_err() {
        runtime.close().await;
    }
    result
}
