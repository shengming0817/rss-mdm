//! Static composition of Registration's account-access execution.
use rss_mdm_registration_service::device_access::execution as access;
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct Assembly {
    pub service: Arc<access::Service>,
    pub worker: Arc<access::worker::Worker>,
    pub materials: Arc<access::Materials>,
}
#[expect(clippy::too_many_arguments, reason = "explicit shared host resources")]
pub(crate) async fn assemble(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: rss_request_context::TenantId,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    recovery: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    reconcile: rss_reconcile_postgres::PgStore,
    budget: Arc<tokio::sync::Semaphore>,
    concurrency: usize,
) -> Result<Assembly, crate::Error> {
    let materials = Arc::new(access::Materials {
        agent_store: Arc::new(super::registration_agent_facts::AgentFacts::new(
            rss_mdm_install_support::StorageProfile::Mdm,
        )),
        source: Arc::new(super::registration_sources::Source(source)),
        capacity: Arc::new(super::capacity::Capacity),
        recovery: recovery.map(|p| {
            Arc::new(rss_mdm_recovery_credentials::access::AccessMaterials::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                p,
                Arc::new(super::recovery_eligibility::AccessEligibility { admission: None }),
            ))
                as Arc<
                    dyn rss_mdm_registration_service::device_access::participants::AccessRecovery,
                >
        }),
        platform: Arc::new(Platform(rss_mdm_apple_channel::flow_store::Store {
            protection,
        })),
    });
    let service = Arc::new(access::Service::new(
        access::Transactions::bind(runtime, tenant, audit, materials.clone())
            .await
            .map_err(super::owner_errors::access)?,
    ));
    let worker = Arc::new(
        access::worker::Worker::new(service.clone(), reconcile, budget, concurrency)
            .map_err(super::owner_errors::access)?,
    );
    Ok(Assembly {
        service,
        worker,
        materials,
    })
}
pub(super) struct Platform(pub(super) rss_mdm_apple_channel::flow_store::Store);
impl rss_mdm_registration_service::device_access::participants::PlatformFacts for Platform {
    fn platform_sso_observation<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        binding: &'a rss_mdm_registration_service::device_access::Binding,
        facts: &'a rss_mdm_agent_wire::runtime::AccessMacPlatformSsoFacts,
    ) -> rss_mdm_registration_service::agent::Pending<'a, bool> {
        use rss_mdm_apple_channel::protocol_types::AppleResults;
        Box::pin(async move {
            self.0
                .platform_sso_observation(c, binding, facts)
                .await
                .map_err(|_| rss_mdm_registration_service::Error::Storage)
        })
    }
}
