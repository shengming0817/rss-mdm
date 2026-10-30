//! Real execution assembled only from the capabilities selected by its test owner.
//! ref: axum 0.8.9 axum/src/routing/mod.rs
use super::{runtime::*, *};

pub(crate) struct Execution {
    pub(crate) materials: Arc<rss_mdm_execution_service::ExecutionMaterials>,
    pub(crate) runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) service: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
}
impl Execution {
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit prepared capabilities keep fixture owners and database roles separate"
    )]
    pub(crate) async fn open(
        authority: &mut authority::Authority,
        config: &Config,
        content: Option<Arc<rss_mdm_content_service::Store>>,
        publications: BTreeMap<
            String,
            Arc<rss_mdm_software_service::publication::PublicationService>,
        >,
        signer: Option<Arc<rss_mdm_execution_service::task_signing::Signer>>,
        recovery: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
        cursor: Vec<u8>,
        resources: &mut Resources,
    ) -> Result<Self> {
        let tenant = authority.identity.tenant;
        let runtime =
            crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
        resources.resource(SourceResource(runtime.clone()));
        let (service, queries, materials) = crate::execution_assembly::assemble(
            config,
            config.native_protector()?,
            authority.audit.clone(),
            content,
            publications,
            runtime.clone(),
            Arc::new(crate::channel_status::Channels::new(config)),
            signer,
            None,
            Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    authority.identity.authority.clone(),
                    tenant,
                ),
            ),
            recovery,
            rss_device_command_postgres::CommandClock::Postgres,
            cursor.clone(),
        )
        .await?;
        resources.resource(rss_mdm_execution_service::Resource(service.clone()));
        authority
            .identity
            .enterprise_platform
            .bind(service.clone())?;
        Ok(Self {
            materials,
            runtime,
            service,
            queries,
        })
    }
}

pub(crate) async fn enrollment(
    authority: &mut authority::Authority,
    config: &Config,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
) -> Result<Arc<rss_mdm_registration_service::agent::Service>> {
    let pki = config
        .agent_pki
        .load(
            &config.identity.instance_id,
            authority.audit.clone(),
            Arc::new(crate::clock::SystemClock),
            crate::device_pki::providers(&config.device_pki)?,
            None,
        )?
        .ok_or_else(|| anyhow::anyhow!("Agent PKI missing"))?;
    super::pki::seed_trust(&authority.pool, &[pki.issuer.trust().trust.clone()]).await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let access_audit = Arc::new(
        authority
            .audit
            .on_runtime(
                authority.identity.runtime.clone(),
                authority.identity.tenant,
                &budget.control(),
            )
            .await?,
    );
    super::agent::application_service(
        access_audit,
        &pki,
        authority.registration.clone(),
        authority.audit.clone(),
        execution,
    )
}

pub(crate) fn routes(
    authority: &authority::Authority,
    enrollment: Arc<rss_mdm_registration_service::agent::Service>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
) -> Router {
    let tasks = Arc::new(crate::agent::TaskState {
        access: Arc::new(rss_mdm_agent_channel::Store::from_pool(
            authority.pool.clone(),
        )),
        enrollment,
        execution,
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                authority.identity.authority.clone(),
                authority.identity.tenant,
            ),
        ),
        authorization: authority.authorization.clone(),
    });
    let envelope = || rss_mdm_agent_channel::boundary::Envelope {
        admission: Arc::new(tokio::sync::Semaphore::new(32)),
        requests: Arc::new(tokio::sync::Semaphore::new(32)),
        host: "mdm.example.test:9445".into(),
        clock: monotonic(),
        audit_store: authority.audit.clone(),
        tenant: authority.identity.tenant.to_string(),
    };
    let timeline = Arc::new(
        rss_mdm_timeline_service::Timeline::new(
            authority.pool.clone(),
            authority.audit.clone(),
            authority.identity.tenant,
            &secret("timeline-cursor"),
        )
        .expect("valid fixture cursor key"),
    );
    {
 rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { api_v1_agent_runtime at "/api/v1/agent/runtime" } }
 RoutesModule1 { api_v1_agent_runtime: {
 rss_mdm_http_contract::route_module! { struct RoutesModule2 for [Browser] { base, rss_mdm_agent_channel_activity_router } }
 RoutesModule2 { base: rss_mdm_agent_channel::task_router(tasks.clone(), envelope()),
rss_mdm_agent_channel_activity_router: rss_mdm_agent_channel::activity_router(tasks, timeline, envelope()) }.assemble()
} }.assemble()
}
        .into_axum()
}
