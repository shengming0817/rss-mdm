//! Recovery receives shared host resources; no capability retains another business service.
use rss_mdm_recovery_credentials::{native, tasks};
use rss_transactional_messaging_postgres::{PgOutboxStore, PgRuntime};
use std::{sync::Arc, time::Duration};
#[derive(Clone)]
pub(crate) struct Assembly {
    pub tasks: Vec<Arc<tasks::Service>>,
    pub worker: Vec<Arc<tasks::worker::Worker>>,
    pub materials: Vec<Arc<tasks::Materials>>,
    pub native: Arc<native::Service>,
    pub native_materials: Arc<native::Materials>,
    pub maintenance: Vec<Arc<rss_mdm_recovery_credentials::maintenance::Maintenance>>,
}
#[expect(clippy::too_many_arguments, reason = "explicit shared host resources")]
pub(crate) async fn assemble(
    discovery_pool: sqlx::PgPool,
    config: &crate::config::Config,
    background: &crate::background::Compiled,
    runtime: Arc<PgRuntime>,
    probe: rss_transactional_messaging::fence::ExecutionBinding,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    credentials: Arc<rss_mdm_recovery_credentials::Protection>,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    reconcile: rss_reconcile_postgres::PgStore,
    budget: Arc<rss_mdm_work_page::capacity::Capacity>,
) -> Result<Assembly, crate::Error> {
    let apple = Arc::new(super::credential_apple_facts::AppleFacts(
        rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        },
    ));
    let native_materials = Arc::new(native::Materials {
        supersede_batch: background.command_supersede_batch,
        credentials: credentials.clone(),
        protection: protection.clone(),
        apple_profiles: apple.clone(),
        apple_results: apple,
    });
    let materials = Arc::new(tasks::Materials {
        accepting: true,
        product: None,
        agent_store: Arc::new(super::registration_agent_facts::AgentFacts::new(
            rss_mdm_install_support::StorageProfile::Mdm,
        )),
        source: Arc::new(super::registration_sources::Source(source)),
        capacity: Arc::new(super::capacity::Capacity),
        recovery_credentials: credentials.clone(),
    });
    let da_materials = Arc::new(tasks::Materials {
        accepting: config.device_access.is_some(),
        product: Some(Arc::new(
            rss_mdm_device_access_postgres::recovery::eligibility::AccessEligibility {
                admission: None,
            },
        )),
        agent_store: materials.agent_store.clone(),
        source: materials.source.clone(),
        capacity: materials.capacity.clone(),
        recovery_credentials: credentials.clone(),
    });
    let materials = vec![materials, da_materials];
    let mut tasks = Vec::new();
    let mut worker = Vec::new();
    for (profile, resources) in [
        rss_mdm_install_support::StorageProfile::Mdm,
        rss_mdm_install_support::StorageProfile::Da,
    ]
    .into_iter()
    .zip(&materials)
    {
        let service = Arc::new(tasks::Service::new(
            tasks::Transactions::bind(
                profile,
                runtime.clone(),
                probe,
                audit.clone(),
                resources.clone(),
            )
            .await
            .map_err(super::owner_errors::credential)?,
        ));
        worker.push(Arc::new(
            tasks::worker::Worker::new(
                discovery_pool.clone(),
                probe.storage(),
                profile,
                service.clone(),
                reconcile.clone(),
                budget.clone(),
            )
            .map_err(super::owner_errors::credential)?,
        ));
        tasks.push(service);
    }
    let transactions = native::Transactions::bind(
        runtime.clone(),
        probe,
        audit.clone(),
        native_materials.clone(),
    )
    .await
    .map_err(super::owner_errors::credential_native)?;
    let delivery = rss_transactional_messaging::policy::DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(6),
        Duration::from_secs(6),
        Duration::from_secs(6),
    )
    .map_err(|_| crate::Error::Malformed)?;
    let outbox = Arc::new(
        PgOutboxStore::new(runtime.clone(), native::messaging_domain(), delivery)
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandStorage))?,
    );
    let native = Arc::new(native::Service::new(
        discovery_pool.clone(),
        probe.storage(),
        transactions,
        outbox,
        reconcile,
        budget.clone(),
        background.command_recovery_batch,
    ));
    let channel = Arc::new(rss_mdm_apple_channel::flow_store::Store {
        protection: protection.clone(),
    });
    let copies = Arc::new(Copies {
        control: rss_mdm_device_service::control::credential_inputs::Copies::bind(
            runtime.clone(),
            probe,
            background.command_supersede_batch,
            protection.clone(),
            Arc::new(super::device_materials::Channel(channel.clone())),
        )
        .await?,
        recovery: native::inputs::Copies::bind(
            runtime.clone(),
            probe,
            background.command_supersede_batch,
            protection,
            channel,
        )
        .await
        .map_err(super::owner_errors::credential_native)?,
    });
    let maintenance = Arc::new(rss_mdm_recovery_credentials::maintenance::Maintenance::new(
        rss_mdm_install_support::StorageProfile::Mdm,
        runtime.clone(),
        discovery_pool.clone(),
        probe.storage(),
        rss_transactional_messaging::fence::Epoch::new(config.storage_binding.epoch)
            .map_err(|_| crate::Error::Malformed)?,
        audit.clone(),
        credentials.clone(),
        Some(copies),
        budget.clone(),
        None,
    ));

    let mut maintenance = vec![maintenance];
    if config.device_access.is_some() {
        let da_maintenance = Arc::new(rss_mdm_recovery_credentials::maintenance::Maintenance::new(
            rss_mdm_install_support::StorageProfile::Da,
            runtime,
            discovery_pool.clone(),
            probe.storage(),
            rss_transactional_messaging::fence::Epoch::new(config.storage_binding.epoch)
                .map_err(|_| crate::Error::Malformed)?,
            audit,
            credentials,
            None,
            budget,
            Some(Arc::new(
                rss_mdm_device_access_postgres::recovery::eligibility::AccessEligibility {
                    admission: None,
                },
            )),
        ));

        maintenance.push(da_maintenance);
    }
    Ok(Assembly {
        tasks,
        worker,
        materials,
        native,
        native_materials,
        maintenance,
    })
}
struct Copies {
    control: rss_mdm_device_service::control::credential_inputs::Copies,
    recovery: native::inputs::Copies,
}
impl rss_mdm_recovery_credentials::cleanup::InputCopies for Copies {
    fn purge_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        operation: uuid::Uuid,
    ) -> rss_mdm_recovery_credentials::cleanup::Pending<
        'a,
        rss_mdm_recovery_credentials::cleanup::CopyState,
    > {
        Box::pin(async move {
            use rss_mdm_recovery_credentials::Error;
            let tenant = tx.tenant_id();
            let (control, recovery) = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok((
                            rss_mdm_device_service::control::storage::owned_ids_on(
                                c,
                                tenant,
                                &[operation],
                            )
                            .await?
                            .contains(&operation),
                            native::storage::owned_ids_on(c, tenant, &[operation])
                                .await?
                                .contains(&operation),
                        ))
                    })
                })
                .await
                .map_err(|_| Error::Storage)?;
            match (control, recovery) {
                (true, false) => self
                    .control
                    .purge_in(tx, operation)
                    .await
                    .map(|purged| {
                        if purged {
                            rss_mdm_recovery_credentials::cleanup::CopyState::Purged
                        } else {
                            rss_mdm_recovery_credentials::cleanup::CopyState::Retained
                        }
                    })
                    .map_err(|e| match e {
                        rss_mdm_device_service::control::transaction::Fault::Request(
                            rss_mdm_device_service::control::Error::CommitUnknown,
                        ) => Error::CommitUnknown,
                        rss_mdm_device_service::control::transaction::Fault::Request(
                            rss_mdm_device_service::control::Error::RollbackFailed,
                        ) => Error::RollbackFailed,
                        rss_mdm_device_service::control::transaction::Fault::Request(
                            rss_mdm_device_service::control::Error::Conflict,
                        ) => Error::Conflict,
                        _ => Error::Storage,
                    }),
                (false, true) => self.recovery.purge_in(tx, operation).await,
                _ => Err(Error::Integrity),
            }
        })
    }
}
