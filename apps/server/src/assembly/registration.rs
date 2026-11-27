//! Enrollment and bootstrap share Registration ownership, with separate durable work scopes.
use rss_mdm_registration_service::{enrollment::tasks, installation as native};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{collections::BTreeMap, sync::Arc};
#[derive(Clone)]
pub(crate) struct Assembly {
    pub enrollment: Arc<tasks::Service>,
    pub worker: Arc<tasks::worker::Worker>,
    pub materials: Arc<tasks::Materials>,
    pub native: Arc<native::Service>,
    pub native_materials: Arc<native::Materials>,
}
#[expect(clippy::too_many_arguments, reason = "explicit host capabilities")]
pub(crate) async fn assemble(
    discovery_pool: sqlx::PgPool,
    config: &crate::config::Config,
    background: &crate::background::Compiled,
    runtime: Arc<PgRuntime>,
    probe: rss_transactional_messaging::fence::ExecutionBinding,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    authority: Arc<rss_mdm_software_service::deployment::managed_registration::AuthorityReader>,
    endpoints: Option<BTreeMap<String, String>>,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    reconcile: rss_mdm_work_page::scheduler::Scheduler,
    budget: Arc<rss_mdm_work_page::capacity::Capacity>,
) -> Result<Assembly, crate::Error> {
    config.enrollment_entries.validate()?;
    let apple = Arc::new(super::registration_apple_facts::AppleFacts(
        rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        },
    ));
    let native_materials = Arc::new(native::Materials {
        supersede_batch: background.command_supersede_batch,
        installations: authority,
        endpoints,
        protection: protection.clone(),
        windows_results: Arc::new(super::registration_windows_facts::WindowsResults(
            rss_mdm_windows_channel::results::Results { protection },
        )),
        apple_profiles: apple.clone(),
        apple_results: apple,
        instance: config.identity.instance_id.clone(),
    });
    let materials = Arc::new(tasks::Materials {
        inventory: Arc::new(super::registration_sources::Inventory::new(
            rss_mdm_install_support::StorageProfile::Mdm,
        )),
        agent_store: Arc::new(super::registration_agent_facts::AgentFacts::new(
            rss_mdm_install_support::StorageProfile::Mdm,
        )),
        source: Arc::new(super::registration_sources::Source(source)),
        capacity: Arc::new(super::capacity::Capacity),
        events: Some(Arc::new(rss_mdm_registration_service::WebhookEvents)),
        instance: config.identity.instance_id.clone(),
    });
    let enrollment = Arc::new(tasks::Service::new(
        tasks::Transactions::bind(
            rss_mdm_install_support::StorageProfile::Mdm,
            runtime.clone(),
            probe,
            audit.clone(),
            materials.clone(),
        )
        .await
        .map_err(super::owner_errors::enrollment)?,
        sessions,
    ));
    let worker = Arc::new(tasks::worker::Worker::new(
        discovery_pool.clone(),
        probe.storage(),
        rss_mdm_install_support::StorageProfile::Mdm,
        enrollment.clone(),
        reconcile.clone(),
        budget.clone(),
    ));
    let transactions =
        native::Transactions::bind(runtime.clone(), probe, audit, native_materials.clone())
            .await
            .map_err(super::owner_errors::installation)?;
    let native = Arc::new(native::Service::new(
        discovery_pool.clone(),
        probe.storage(),
        transactions,
        reconcile,
        budget,
        background.command_recovery_batch,
    ));

    Ok(Assembly {
        enrollment,
        worker,
        materials,
        native,
        native_materials,
    })
}
