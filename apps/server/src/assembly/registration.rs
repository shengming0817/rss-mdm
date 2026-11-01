//! Enrollment and bootstrap share Registration ownership, with separate durable work scopes.
use rss_mdm_registration_service::{enrollment::tasks, installation as native};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgOutboxStore, PgRuntime};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
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
    config: &crate::config::Config,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    authority: Arc<rss_mdm_software_service::deployment::managed_registration::AuthorityReader>,
    endpoints: Option<BTreeMap<String, String>>,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    reconcile: rss_reconcile_postgres::PgStore,
    budget: Arc<tokio::sync::Semaphore>,
) -> Result<Assembly, crate::Error> {
    config.enrollment_entries.validate()?;
    let apple = Arc::new(super::registration_apple_facts::AppleFacts(
        rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        },
    ));
    let native_materials = Arc::new(native::Materials {
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
        inventory: Arc::new(super::registration_sources::Inventory),
        agent_store: Arc::new(super::registration_agent_facts::AgentFacts),
        source: Arc::new(super::registration_sources::Source(source)),
        capacity: Arc::new(super::capacity::Capacity),
        instance: config.identity.instance_id.clone(),
    });
    let enrollment = Arc::new(tasks::Service::new(
        tasks::Transactions::bind(runtime.clone(), tenant, audit.clone(), materials.clone())
            .await
            .map_err(super::owner_errors::enrollment)?,
        sessions,
    ));
    let worker = Arc::new(
        tasks::worker::Worker::new(
            enrollment.clone(),
            reconcile.clone(),
            budget.clone(),
            config.background.device_concurrency,
        )
        .map_err(super::owner_errors::enrollment)?,
    );
    let transactions =
        native::Transactions::bind(runtime.clone(), tenant, audit, native_materials.clone())
            .await
            .map_err(super::owner_errors::installation)?;
    let delivery = rss_transactional_messaging::policy::DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(6),
        Duration::from_secs(6),
        Duration::from_secs(6),
    )
    .map_err(|_| crate::Error::Malformed)?;
    let outbox = Arc::new(
        PgOutboxStore::new(runtime, native::messaging_domain(), delivery)
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandStorage))?,
    );
    let native = Arc::new(native::Service::new(
        transactions,
        outbox,
        reconcile,
        budget,
        config.background.device_concurrency,
    ));

    Ok(Assembly {
        enrollment,
        worker,
        materials,
        native,
        native_materials,
    })
}
