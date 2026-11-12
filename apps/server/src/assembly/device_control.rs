//! Device control and retirement consume explicit owner participants.
use super::host_storage::Storage;
use crate::Error;
use rss_mdm_device_service::control::{Service, deadline};
use std::sync::Arc;
pub(crate) async fn assemble(
    config: &crate::config::Config,
    storage: &Storage,
    protection: Arc<rss_mdm_native_protection::Protector>,
    recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    software: Arc<rss_mdm_software_service::deployment::Transactions>,
    configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
    command_clock: rss_device_command_postgres::CommandClock,
) -> Result<
    (
        Arc<Service>,
        Arc<rss_mdm_device_service::control::queries::Queries>,
    ),
    Error,
> {
    let caller = storage.runtime.clone();
    let (outbox, store) = storage
        .runtime
        .local_tx(storage.tenant, deadline(), move |tx| {
            Box::pin(super::host_storage::bind_command_in(
                caller,
                tx,
                command_clock,
                rss_mdm_device_service::control::messaging_domain(),
            ))
        })
        .await
        .fold(
            Ok,
            |_| Err(Error::Unavailable(crate::Failure::CommandStorage)),
            |_| Err(Error::Unavailable(crate::Failure::CommandStorage)),
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(crate::Failure::CommandStorage)),
        )?;
    let agent_store: Arc<dyn rss_mdm_device_service::control::agent_facts::Store> =
        Arc::new(super::agent_facts::AgentFacts);
    let windows_results: Arc<dyn rss_mdm_device_service::control::windows_results::Store> =
        Arc::new(super::windows_results::WindowsResults(
            rss_mdm_windows_channel::results::Results {
                protection: protection.clone(),
            },
        ));
    let apple_store = Arc::new(super::apple_facts::AppleFacts(
        rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        },
    ));
    let queries = Arc::new(rss_mdm_device_service::control::queries::Queries::new(
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        rss_mdm_device_service::control::queries::Dependencies {
            read_pool: storage.read_pool.clone(),
            protection: protection.clone(),
            windows_results: windows_results.clone(),
            apple_results: apple_store.clone(),

            runtime: storage.runtime.clone(),
            tenant: storage.tenant,
        },
    ));
    let configuration_cleanup =
        Arc::new(super::configuration_cleanup::Cleanup(configuration.clone()));

    let service = Arc::new(Service::new(
        rss_mdm_device_service::control::Dependencies {
            retirement: Arc::new(crate::registration_lifecycle::Bridge),
            worker_budget: storage.worker_budget.clone(),
            capacity: Arc::new(super::capacity::Capacity),
            task_cleanup: Arc::new(super::task_cleanup::Cleanup(software)),
            configuration_cleanup,
            worker_concurrency: config.background.device_concurrency,
            lock_pins: recovery_credentials.as_ref().map(|p| {
                Arc::new(super::device_materials::Pins(
                    rss_mdm_recovery_credentials::lock_pin::LockPins::new(p.clone()),
                )) as Arc<dyn rss_mdm_device_service::control::lock_pin::LockPins>
            }),

            source: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
            protection: protection.clone(),

            agent_store,
            apple_profiles: apple_store.clone(),
            windows_results: windows_results.clone(),
            apple_results: apple_store.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                rss_mdm_install_support::StorageProfile::Mdm,
                storage.runtime.clone(),
                storage.tenant,
            ),
            audit_store: storage.audit.clone(),
            runtime: storage.runtime.clone(),
            outbox,
            store,
            reconcile: storage.reconcile.clone(),
            reconcile_messaging: rss_reconcile_postgres::PgMessagingStore::new(
                storage.runtime.clone(),
                storage.tenant,
                deadline(),
            )
            .await
            .map_err(|_| Error::Configuration(crate::ConfigIssue::CommandStorage))?,
            tenant: storage.tenant,
            instance: config.identity.instance_id.clone(),
        },
    ));

    Ok((service, queries))
}
