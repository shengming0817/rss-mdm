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
    let probe = config.management_binding()?;
    let supersede_batch = storage.command_supersede_batch;
    let caller = storage.runtime.clone();
    let (outbox, store) = storage
        .runtime
        .local_tx(probe, deadline(), move |tx| {
            Box::pin(super::host_storage::bind_command_in(
                caller,
                tx,
                command_clock,
                supersede_batch,
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
        },
    ));
    let configuration_cleanup =
        Arc::new(super::configuration_cleanup::Cleanup(configuration.clone()));

    let service = Arc::new(Service::new(
        rss_mdm_device_service::control::Dependencies {
            read_pool: storage.discovery_pool.clone(),
            retirement: Arc::new(crate::registration_lifecycle::Bridge),
            worker_budget: storage.worker_budget.clone(),
            capacity: Arc::new(super::capacity::Capacity),
            task_cleanup: Arc::new(super::task_cleanup::Cleanup(software)),
            configuration_cleanup,
            recovery_batch: storage.command_recovery_batch,
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
            ),
            audit_store: storage.audit.clone(),
            runtime: storage.runtime.clone(),
            outbox,
            store,
            reconcile: storage.reconcile.clone(),
            reconcile_messaging: Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
                storage.runtime.clone(),
                probe,
                deadline(),
            ))
            .await
            .map_err(|_| Error::Configuration(crate::ConfigIssue::CommandStorage))?,
            probe,
            instance: config.identity.instance_id.clone(),
        },
    ));

    Ok((service, queries))
}

pub(crate) struct Changes {
    pub snapshot: super::query_snapshot::QuerySnapshot,
    pub device_control: Arc<rss_mdm_device_service::control::Service>,
}
impl rss_mdm_management_http::device_control::Changes for Changes {
    fn change<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        device: &'a rss_mdm_agent_wire::DeviceId,
        id: uuid::Uuid,
        change: &'a rss_mdm_device_service::control::Change,
        reauthorization: Option<
            &'a rss_mdm_device_service::control::device_control::Reauthorization,
        >,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> rss_mdm_management_http::Pending<'a, rss_mdm_device_service::control::ChangedReceipt> {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            let owner = self
                .snapshot
                .read(request, (proof, device, id), |ctx, c, grant, _| {
                    Box::pin(async move {
                        let (p, d, id) = *ctx;
                        grant.require(
                            p,
                            rss_mdm_authorization_service::Permission::OperationRead,
                            Some(d),
                        )?;
                        super::native_ownership::on_device(c, p.binding().tenant(), d, id)
                            .await
                            .map_err(Into::into)
                    })
                })
                .await?;
            // Only direct device controls support management cancel/reauthorization; policies own desired work.
            if owner != super::native_ownership::Owner::Device {
                return Err(rss_mdm_management_http::Error::Conflict);
            }
            self.device_control
                .change(proof, device, id, change, reauthorization, audit)
                .await
                .map_err(Into::into)
        })
    }
}
