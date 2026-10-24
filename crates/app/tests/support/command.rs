//! Minimal command service; no full application or platform material preparation.
use super::runtime::case_tenant;
use std::{sync::Arc, time::Duration};

pub(crate) async fn command_service(
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    command_clock: rss_device_command_postgres::CommandClock,
) -> anyhow::Result<(
    Arc<rss_mdm_execution_service::ExecutionService>,
    Arc<rss_mdm_execution_service::queries::Queries>,
    Arc<rss_transactional_messaging_postgres::PgRuntime>,
)> {
    let config = crate::test_support::identity::config(case_tenant())?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let protection = config.native_protector()?;
    let content = None;
    let runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let built = async {
        let audit_store = Arc::new(
            audit
                .on_runtime(runtime.clone(), tenant, &budget.control())
                .await?,
        );
        let task_signing_audit = audit.clone();
        let (outbox, store, reconcile) = crate::execution_assembly::open_storage(
            runtime.clone(),
            config.execution.database.options()?,
            tenant,
            &protection,
            command_clock,
        )
        .await?;
        let channels = Arc::new(crate::channel_status::Channels::new(&config));
        let signer = None;
        let source: Arc<dyn rss_mdm_execution_service::source_authority::SourceAuthority> =
            Arc::new(
                rss_mdm_flow_service::planning::execution_source::ExecutionSource {
                    objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
                        audit_store.clone(),
                    )),
                    mdm_software_enabled: config.software_distribution.mdm_enabled,
                },
            );
        let agent_store: Arc<dyn rss_mdm_execution_service::channels::Agent> =
            Arc::new(rss_mdm_agent_channel::Bindings);
        let apple_store = Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        });
        let software = Arc::new(rss_mdm_software_service::preparation::Preparation::new(
            rss_mdm_software_service::catalog::Reader::new(tenant),
            std::collections::BTreeMap::<
                String,
                Arc<rss_mdm_software_service::publication::PublicationService>,
            >::new()
            .into_iter()
            .map(|(name, service)| (name, Arc::new(service.exports())))
            .collect(),
        ));
        let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(
            rss_mdm_execution_service::InputDependencies {
                software_distribution: config.software_distribution,
                product_origin: config.product_origin.clone(),
                recovery_enabled: config.recovery_credentials.is_some(),
                protection: protection.clone(),
                software,
                bootstrap: None,
                enrollment_entries: config.enrollment_entries.clone(),
                runtime: runtime.clone(),
                tenant,
                content: content.clone(),
                signing_enabled: signer.is_some(),
                agent_installation: channels.clone(),
            },
        ));
        let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(
            rss_mdm_execution_service::queries::Dependencies {
                source: source.clone(),
                protection: protection.clone(),
                agent_store: agent_store.clone(),
                apple_results: apple_store.clone(),
                policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
                runtime: runtime.clone(),
                tenant,
                inputs: inputs.clone(),
                signed: signer.is_some(),
                content_available: content.is_some(),
            },
        ));
        let service = Arc::new(rss_mdm_execution_service::ExecutionService::new(
            rss_mdm_execution_service::Dependencies {
                recovery_credentials: None,
                sessions: sessions.clone(),
                source,
                protection: protection.clone(),
                inputs: inputs.clone(),
                agent_store,
                apple_profiles: apple_store.clone(),
                apple_push: apple_store.clone(),
                apple_collections: apple_store.clone(),
                apple_results: apple_store.clone(),
                policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
                audit_store,
                task_signing_audit,
                runtime: runtime.clone(),
                outbox,
                store,
                reconcile,
                tenant,
                instance: config.identity.instance_id.clone(),
                content: content.clone(),
                signer,
            },
        ));

        Ok::<_, anyhow::Error>((service, queries))
    }
    .await;
    let (service, queries) = match built {
        Ok(value) => value,
        Err(error) => {
            runtime.close().await;
            return Err(error);
        }
    };
    Ok((service, queries, runtime))
}
