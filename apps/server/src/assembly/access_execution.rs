//! Static composition of Registration's account-access execution.
use rss_mdm_device_access_postgres::device_access::execution as access;
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct Assembly {
    pub service: Arc<access::Service>,
    pub worker: Arc<access::worker::Worker>,
}
#[allow(
    clippy::too_many_arguments,
    reason = "keep execution scope and existing operation inputs explicit"
)]
pub(crate) async fn assemble(
    discovery_pool: sqlx::PgPool,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    probe: rss_transactional_messaging::fence::ExecutionBinding,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    recovery: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    reconcile: rss_reconcile_postgres::PgStore,
    budget: Arc<rss_mdm_work_page::capacity::Capacity>,
    enabled: bool,
) -> Result<Assembly, crate::Error> {
    let materials = Arc::new(access::Materials {
        accepting: enabled,
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
        access::Transactions::bind(runtime, probe, audit, materials.clone())
            .await
            .map_err(super::owner_errors::access)?,
    ));
    let worker = Arc::new(
        access::worker::Worker::new(
            discovery_pool.clone(),
            probe.storage(),
            service.clone(),
            reconcile,
            budget,
        )
        .map_err(super::owner_errors::access)?,
    );
    Ok(Assembly { service, worker })
}
