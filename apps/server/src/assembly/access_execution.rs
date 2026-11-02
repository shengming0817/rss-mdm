//! Static composition of Registration's account-access execution.
use rss_mdm_device_access_postgres::device_access::execution as access;
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct Assembly {
    pub service: Arc<access::Service>,
    pub worker: Arc<access::worker::Worker>,
}
pub(crate) async fn assemble(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: rss_request_context::TenantId,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    recovery: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    reconcile: rss_reconcile_postgres::PgStore,
    budget: Arc<tokio::sync::Semaphore>,
    concurrency: usize,
) -> Result<Assembly, crate::Error> {
    let materials = Arc::new(access::Materials {
        agent_store: Arc::new(super::registration_agent_facts::AgentFacts::new(
            rss_mdm_install_support::StorageProfile::Mdm,
        )),
        capacity: Arc::new(super::capacity::Capacity),
        recovery: recovery.map(|p| {
            Arc::new(
                rss_mdm_device_access_postgres::recovery::AccessMaterials::new(
                    p,
                    Arc::new(
                        rss_mdm_device_access_postgres::recovery::eligibility::AccessEligibility {
                            admission: None,
                        },
                    ),
                ),
            )
                as Arc<
                    dyn rss_mdm_device_access_postgres::device_access::participants::AccessRecovery,
                >
        }),
        platform: Arc::new(rss_mdm_device_access_postgres::platform_sso::Observation),
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
    Ok(Assembly { service, worker })
}
