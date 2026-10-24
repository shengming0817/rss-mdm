//! Successful command preparation; behavioral assertions live in their owning module.
use crate::test_support::http::Browser;
use anyhow::ensure;
use axum::{
    Router,
    http::{Method, StatusCode},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_execution_service::{deadline, messaging_domain};
use rss_transactional_messaging_postgres::PgOutboxStore;
use serde_json::{Value, json};
pub(crate) use std::{sync::Arc, time::Duration};
pub(crate) use uuid::Uuid;
#[path = "support/configuration.rs"]
pub(crate) mod configuration;
#[path = "support/native.rs"]
pub(crate) mod native;
pub(crate) fn case_tenant() -> &'static str {
    crate::test_support::case::tenant()
}
pub(crate) fn case_device() -> &'static str {
    crate::test_support::case::name("tls-device")
}
pub(crate) struct Client {
    pub(crate) browser: Browser,
    pub(crate) router: Router,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) execution_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) clock: Arc<dyn crate::clock::Clock>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) operation: Uuid,
    rule: Uuid,
    rule_revision: u64,
}
impl Client {
    pub(crate) async fn start(
        router: Router,
        app: &crate::api::Assembly,
    ) -> anyhow::Result<Self> {
        let secret = crate::test_support::identity::credential_for(case_tenant(), "admin")?;
        Ok(Self::with_browser(
            router,
            app,
            Browser {
                cookies: std::collections::BTreeMap::from([(
                    "__Host-identity-session".into(),
                    secret.expose().into(),
                )]),
                csrf: Some(secret.csrf()),
                ..Browser::default()
            },
        ))
    }

    pub(crate) fn with_browser(
        router: Router,
        app: &crate::api::Assembly,
        browser: Browser,
    ) -> Self {
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse().expect("fixture address"),
        )));
        Self {
            browser,
            router,
            execution: app.execution.clone(), execution_runtime: app.execution_runtime.clone(),
            audit_store: app.audit_store.clone(), tenant: app.identity.tenant, clock: app.clock.clone(),
            protection: app.protection.clone(),
            sessions: Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(app.identity.authority.clone(), app.identity.tenant)),
            operation: Uuid::new_v4(),
            rule: Uuid::new_v4(),
            rule_revision: 0,
        }
    }
    pub(crate) async fn call(
        &mut self,
        method: Method,
        suffix: &str,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        self.browser
            .call(
                &self.router,
                method,
                &format!(
                    "/api/v1/devices/{DEVICE}/operations{suffix}",
                    DEVICE = case_device()
                ),
                body,
            )
            .await
    }
    pub(crate) async fn set_authorized(&mut self, enabled: bool) -> anyhow::Result<()> {
        let mut permissions = vec!["operation_read", "operation_cancel"];
        if enabled {
            permissions.push("device_control");
        }
        let grants: Vec<_> = permissions
            .iter()
            .map(|p| json!({"operation":p,"scope":{"kind":"device","id":case_device()}}))
            .collect();
        let value = json!({"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants});
        let response=self.browser.call(&self.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",self.rule),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":self.rule_revision,"value":value}))).await?;
        ensure!(response.0 == StatusCode::OK, "grant update {:?}", response);
        self.rule_revision += 1;
        Ok(())
    }
    pub(crate) async fn publish_operation(&self, id: Uuid) -> anyhow::Result<()> {
        for _ in 0..16 {
            self.execution.relay_once().await?;
        }
        let audit = RequestAudit::new(case_tenant().into(), "management_read");
        let service = self.execution.as_ref();
        let result = service.recover_operation(id, &audit).await;
        audit.finalize(None);
        result?;
        Ok(())
    }
    pub(crate) async fn known_windows_capability(&self, device: &str) -> anyhow::Result<()> {
        use sqlx::Connection;
        let mut c =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("INSERT INTO mdm_commands.capabilities(tenant_id,registration,generation,os_version,edition,session,observed_at) SELECT tenant_id,id,generation,'10.0.22621.0',48,1,floor(extract(epoch FROM clock_timestamp()))::bigint FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND purpose='primary' AND channel='mdm' AND state='active' ON CONFLICT(tenant_id,registration) DO NOTHING")
            .bind(case_tenant()).bind(device).execute(&mut c).await?;
        c.close().await?;
        Ok(())
    }
    pub(crate) async fn accept_authorized(&mut self) -> anyhow::Result<()> {
        self.set_authorized(true).await?;
        let request = json!({"operationId":self.operation,"action":{"kind":"restart"},"deadline":self.clock.unix_seconds()?+300});
        ensure!(self.call(Method::POST, "", Some(request)).await?.0 == StatusCode::ACCEPTED);
        ensure!(
            self.call(
                Method::POST,
                &format!("/{}/reauthorize", self.operation),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0 == StatusCode::OK
        );
        Ok(())
    }
}
impl Client {
    pub(crate) fn command_worker(
        &self,
        signals: Arc<crate::worker_wake::Signals>,
    ) -> anyhow::Result<rss_runtime::ShutdownStack> {
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = owner.startup()?.commit();
        launch.stage_deferred_task_with_token(
            self.execution
                .clone()
                .registration(signals.execution())
                .critical(),
        );
        launch.finish();
        Ok(owner)
    }
}
pub(crate) async fn ordinary(
    command_clock: rss_device_command_postgres::CommandClock,
) -> anyhow::Result<(crate::test_support::authority::Authority, Client)> {
    use crate::test_support::runtime::Resources;
    let (resources, (mut authority, client)) = Resources::build(move |resources| Box::pin(async move {
        let config = crate::test_support::identity::config(case_tenant())?;
        let mut authority = crate::test_support::authority::Authority::open().await?;
        resources.extend(std::mem::take(&mut authority.resources));
        let tenant = authority.identity.tenant;
        let protection = config.native_protector()?;
        let content = None;
        let runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
                    let built = async {
                    let audit_store = Arc::new(authority.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
                    let task_signing_audit = authority.audit.clone();
                    let (outbox, store, reconcile) = crate::execution_assembly::open_storage(runtime.clone(), config.execution.database.options()?, tenant, &protection, command_clock).await?;
                    let channels = Arc::new(crate::channel_status::Channels::new(&config));
                    let signer = None;
                    let sessions = Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(), tenant));
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
            std::collections::BTreeMap::<String, Arc<rss_mdm_software_service::publication::PublicationService>>::new()
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

                    Ok::<_, anyhow::Error>((service, queries, sessions))
                    }.await;
                    let (service, queries, sessions) = match built {
                        Ok(value) => value,
                        Err(error) => { runtime.close().await; return Err(error); }
                    };
                    resources.resource(rss_mdm_execution_service::Resource(service.clone()));

        let cursor = rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?;
        let router = authority.router(Router::new().nest("/api/v1", rss_mdm_management_http::execution::http::routes(queries, cursor)
            .with_state(Arc::new(rss_mdm_management_http::execution::http::HttpState { execution: service.clone(), windows: true, apple: false })).into_axum()).merge(authority.authorization()))?;
        let devices = crate::device::DeviceService::new(authority.registration.clone(), tenant.to_string(), authority.audit.clone());
        let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
        let credential = crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 91);
        crate::device::test_support::bind(&devices, &proof, &credential, case_device(), 0).await?;
        let client = Client {
            router, browser: authority.browser("admin")?, execution: service, execution_runtime: runtime,
            audit_store: authority.audit.clone(), sessions, tenant, clock: Arc::new(crate::clock::SystemClock), protection,
            operation: Uuid::new_v4(), rule: Uuid::new_v4(), rule_revision: 0,
        };
        client.known_windows_capability(case_device()).await?;
        Ok((authority, client))
    })).await?;
    authority.resources = resources;
    Ok((authority, client))
}
#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "subprocess killed by command T2 after confirmed PG acceptance"]
async fn relay_crash_child() -> anyhow::Result<()> {
    use rss_transactional_messaging::{outbox::OutboxRelayStore, policy::DeliveryBudget};
    let config = crate::test_support::identity::config(case_tenant())?;
    let authority = crate::test_support::authority::Authority::open().await?;
    let service = Box::pin(crate::execution_assembly::open(
        &config,
        config.native_protector()?,
        authority.audit.clone(),
        crate::execution_assembly::open_content(&config, config.native_protector()?).await?,
        std::collections::BTreeMap::new(),
        rss_device_command_postgres::CommandClock::Postgres,
        Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                authority.identity.authority.clone(),
                authority.identity.tenant,
            ),
        ),
    ))
    .await?;
    let relay = PgOutboxStore::<()>::new(
        service.runtime.clone(),
        messaging_domain(),
        DeliveryBudget::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?,
    )?;
    let claims = relay
        .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
        .await?;
    ensure!(claims.len() == 1);
    for claim in claims {
        let message = PgOutboxStore::<()>::message(&claim);
        let id = Uuid::parse_str(
            message
                .message_id()
                .as_str()
                .strip_prefix("dispatch.")
                .unwrap(),
        )?;
        ensure!(
            id.to_string() == std::env::var("MDM_CRASH_OPERATION")?,
            "child claimed another operation"
        );
        let digest = message.fingerprint().as_bytes().to_vec();
        service.service.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitAcknowledgedPending,
        );
        service.service.accept_dispatch(id, digest).await?;
    }
    anyhow::bail!("parent must kill before completion")
}
