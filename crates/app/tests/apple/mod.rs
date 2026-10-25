#![allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and persistence assertions"
)]
//! Real Apple mTLS participant and fixed external SCEP provider; no principal or status stubs.
mod account_enrollment;
mod ade;
mod commands;
mod ddm;
mod lifecycle;
mod onboarding;
mod oracle;
mod platform_sso;
mod policy;
mod scep;
#[path = "support/scep.rs"]
mod scep_client;
mod users;
use super::*;
use crate::{
    clock::Clock,
    native::{self},
    test_support::http::Browser,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use rss_mdm_apple_mdm::protocol;
use serde_json::json;
use std::{path::PathBuf, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;
fn case_tenant() -> &'static str {
    crate::test_support::case::tenant()
}
fn case_device() -> &'static str {
    crate::test_support::case::name("apple-native-mac")
}
struct Fixture {
    resources: crate::test_support::runtime::Resources,
    authority: crate::test_support::authority::Authority,
    commands: crate::execution_assembly::Assembly,
    planning: Arc<crate::planning::Planning>,
    assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
    apple: Arc<Apple>,
    devices: Arc<crate::device::DeviceService>,
    associations: Arc<rss_mdm_device_service::Associations>,
    clock: Arc<dyn crate::clock::Clock>,
    inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    requests: Arc<tokio::sync::Semaphore>,
    agent_enrollment: Option<Arc<rss_mdm_registration_service::agent::Service>>,
    agent_channel: Option<crate::native::ChannelRouter>,
    browser: Browser,
    router: Router,
    owner: Option<rss_runtime::ShutdownStack>,
    execution_owner: Option<rss_runtime::ShutdownStack>,
    signals: Arc<crate::worker_wake::Signals>,
    root: PathBuf,
    lose_notify: Arc<std::sync::atomic::AtomicBool>,
    pause_before_notify: Arc<std::sync::atomic::AtomicBool>,
    ade: Arc<rss_mdm_apple_channel::HttpState>,
}
impl Fixture {
    async fn start() -> Result<Self> {
        Self::with_endpoint(false, None, false).await
    }
    async fn with_agent() -> Result<Self> {
        Self::with_endpoint(true, None, false).await
    }
    async fn with_endpoint(
        agent: bool,
        address: Option<std::net::SocketAddr>,
        preserve_authorization: bool,
    ) -> Result<Self> {
        Self::with_ade_endpoint(agent, address, preserve_authorization, None).await
    }
    async fn with_ade_endpoint(
        agent: bool,
        address: Option<std::net::SocketAddr>,
        preserve_authorization: bool,
        ade: Option<rss_mdm_apple_channel::ade::Fixture>,
    ) -> Result<Self> {
        Self::with_options(agent, address, preserve_authorization, ade, false, false).await
    }
    async fn with_mdm_software() -> Result<Self> {
        Self::with_options(false, None, false, None, true, false).await
    }
    async fn with_options(
        agent: bool,
        address: Option<std::net::SocketAddr>,
        preserve_authorization: bool,
        ade: Option<rss_mdm_apple_channel::ade::Fixture>,
        mdm_software: bool,
        platform_sso: bool,
    ) -> Result<Self> {
        Self::with_platform_configuration(
            agent,
            address,
            preserve_authorization,
            ade,
            mdm_software,
            platform_sso,
            None,
        )
        .await
    }
    async fn with_platform_configuration(
        agent: bool,
        address: Option<std::net::SocketAddr>,
        preserve_authorization: bool,
        ade: Option<rss_mdm_apple_channel::ade::Fixture>,
        mdm_software: bool,
        platform_sso: bool,
        platform_configuration: Option<config::PlatformSso>,
    ) -> Result<Self> {
        let (resources, mut fixture) = crate::test_support::runtime::Resources::build(move |resources| Box::pin(async move {
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let manage =
            tokio::net::TcpListener::bind(address.unwrap_or("127.0.0.1:0".parse()?)).await?;
        let webhook = tokio::net::TcpListener::bind(
            std::env::var("MDM_APPLE_WEBHOOK_LISTEN").unwrap_or_else(|_| "127.0.0.1:0".into()),
        )
        .await?;
        if std::env::var_os("MDM_APPLE_WEBHOOK_LISTEN").is_some() {
            publish_webhooks(webhook.local_addr()?).await?;
        }
        let mut config = crate::test_support::identity::config(case_tenant())?;
        config.native_protocols.windows = None;
        config.software_distribution.mdm_enabled = mdm_software;
        let mut apple: config::Config =
            serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
        apple.management.origin = format!("https://localhost:{}", manage.local_addr()?.port());
        let mut trust: rss_mdm_agent_wire::pki::Trust =
            serde_json::from_slice(&std::fs::read(&apple.trust_file)?)?;
        trust.origin = apple.management.origin.clone();
        let trust_path = root.join(format!("host-trust-{}.json", manage.local_addr()?.port()));
        std::fs::write(&trust_path, serde_json::to_vec(&trust)?)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&trust_path, std::fs::Permissions::from_mode(0o600))?;
        apple.trust_file = trust_path;
        if platform_sso {apple.platform_sso=Some(match platform_configuration{Some(c)=>c,None=>platform_sso::configuration(&root)?});}
        config.native_protocols.apple = Some(apple);
        let compiled = config.compile()?;
        let config = &compiled.config;
        let clock = Arc::new(crate::clock::SystemClock);
        let monotonic: Arc<dyn rss_observation::Clock> = fixture_clock();
        let (pool, source, audit) = crate::audit_test_support::request_store().await?;
        resources.resource(crate::test_support::runtime::PoolResource(pool.clone()));
        resources.resource(crate::test_support::runtime::SourceResource(source));
        let registration = Arc::new(rss_mdm_registration_service::Store::from_pool(pool.clone(), Arc::new(crate::registration_lifecycle::Bridge)));
        let authorization = Arc::new(rss_mdm_authorization_service::Store::from_pool(pool.clone(), Arc::new(crate::lifecycle::RuntimeTimer)));
        let devices = Arc::new(crate::device::DeviceService::new(registration.clone(), case_tenant().into(), audit.clone()).with_retirement_test_budget(Duration::from_secs(30)));
        let runtime = crate::inventory_runtime::InventoryRuntime::fixture(config.runtime_database.options()?, Arc::new(rss_mdm_inventory_service::Store::from_pool(pool.clone())),
            rss_request_context::TenantId::parse(case_tenant())?, monotonic.clone(), audit.clone()).await?;
        resources.resource(crate::test_support::runtime::InventoryFixtureResource(runtime.clone()));
        let content = crate::execution_assembly::open_content(config, config.native_protector()?).await?;
        if let Some(content) = &content {
            resources.resource(crate::execution_assembly::ContentResource(content.clone()));
        }
        let identity = crate::identity::Identity::connect(
            config,
            compiled.identity_management.clone(),
            Some(crate::apple::identity_platform(config).await?),
            |resource| resources.acquire(resource),
        )
        .await?;
        let execution = crate::execution_assembly::open(
            config,
            config.native_protector()?,
            audit.clone(),
            content,
            std::collections::BTreeMap::new(),
            rss_device_command_postgres::CommandClock::Postgres,
            Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    identity.authority.clone(),
                    identity.tenant,
                ),
            ),
        )
        .await?;
        resources.resource(rss_mdm_execution_service::Resource(
            execution.service.clone(),
        ));
        let config = compiled.config;
        let agent_audit = audit.clone();
        let agent_pki = if agent { config.agent_pki.load(
            &config.identity.instance_id,
            agent_audit.clone(),
            clock.clone(),
            crate::device_pki::providers(&config.device_pki)?,
            config.agent_pki.bootstrap_materials(&config.identity.instance_id,crate::device_pki::providers(&config.device_pki)?.as_ref(), clock.unix_seconds()?)?,
        )? } else { None };
        let access_audit=Arc::new(agent_audit.on_runtime(identity.runtime.clone(),identity.tenant,&rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5)).control()).await?);
        let agent_enrollment = agent_pki
            .as_ref()
            .map(|pki| {
                crate::test_support::agent::application_service(
                    access_audit.clone(),
                    pki,
                    registration.clone(),
                    agent_audit.clone(),
                    execution.service.clone(),
                )
            })
            .transpose()?;
        let mut apple = Apple::load(
            execution.protection.clone(),
            config.native_protocols.apple.unwrap(),
            fixture_materials(&root)?,
            crate::clock::SystemClock.unix_seconds()?,
            (&config.product_origin,identity.tenant),
            crate::device_pki::providers(&config.device_pki)?,
        )?;
        if let Some(ade) = ade {
            apple.channel = Arc::new(
                Arc::try_unwrap(apple.channel)
                    .map_err(|_| anyhow::anyhow!("shared fixture channel"))?
                    .with_ade_fixture(ade),
            );
        }
        let apple = Arc::new(apple);
        let mut trusts = vec![apple.channel.device_trust().clone()];
        if let Some(a) = &agent_pki {
            trusts.push(a.issuer.trust().trust.clone());
            if let Some(bootstrap) = &a.bootstrap {
                trusts.push(bootstrap.trust.clone());
            }
        }
        let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
            pool.clone(),
            agent_audit.clone(),
            trusts,
            crate::device_pki::providers(&config.device_pki)?,
        ));
        crate::test_support::pki::seed_trust(&pool.clone(), pki.bindings()).await?;
        let associations = Arc::new(rss_mdm_device_service::Associations::new(
            audit.clone(),
            rss_request_context::TenantId::parse(case_tenant())?,
            &[7; 32],
        )?);
        // This handler fixture owns its real transport outside production assembly.
        if let Some(agent) = &agent_pki {
            execution.channels.set(crate::channel_status::ChannelName::Agent,
                crate::channel_status::ChannelState::Ready, None)?;
            execution.channels.mounted(crate::channel_status::ChannelName::Agent)?;
            execution.channels.installation(agent.clone(), pki.clone())?;
        }
        let platform_configuration = apple.platform_sso.as_ref().map(|rt| rt.qualification_configuration()).transpose()?;
        let identity = Arc::new(identity);
        let credentials = Arc::new(crate::enrollment::credentials::Credentials::new(monotonic.clone(), 100));
        let authority = crate::test_support::authority::Authority {
            resources: Default::default(), base: serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?, pool: pool.clone(), registration: registration.clone(), authorization: authorization.clone(),
            identity: identity.clone(), credentials: credentials.clone(), audit: audit.clone(),
        };
        let tenant = identity.tenant;
        let plan_runtime = crate::planning::test_support::runtime(tenant).await;
        resources.resource(crate::test_support::runtime::SourceResource(plan_runtime.clone()));
        let key = rss_mdm_flow_service::storage::cursor_key(&plan_runtime, tenant).await?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let plan_audit = Arc::new(audit.on_runtime(plan_runtime.clone(), tenant, &budget.control()).await?);
        let planning = Arc::new(crate::planning::Planning::new(plan_audit.clone(), plan_runtime.clone(), tenant,
            Arc::new(crate::clock::FlowClock(clock.clone())), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(plan_audit.clone()))).await?);
        let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
        let compliance = crate::planning::test_support::compliance(&planning).await;
        let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(runtime.clone(), plan_audit.clone(), plan_runtime.clone(), tenant,
            Arc::new(crate::clock::InventoryClock(clock.clone())), &key, Arc::new(crate::automation::inventory_tasks::InventoryTasks)));
        let catalog = crate::flow::catalog(plan_audit.clone(), plan_runtime.clone(), tenant, clock.clone()).await?;
        let policies = Arc::new(rss_mdm_flow_service::planning::policies::Policies::new(&key, plan_runtime.clone(), plan_audit.clone(), tenant,
            Arc::new(rss_mdm_policy_postgres::PolicyStore::new(plan_runtime.clone(), tenant, crate::identity::deadline()).await?), execution.inputs.clone()));
        let sessions = Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(identity.authority.clone(), tenant));
        let requests = Arc::new(tokio::sync::Semaphore::new(4));
        let ade = Arc::new(rss_mdm_apple_channel::HttpState {
            platform_sso: apple.platform_sso.clone(), platform_objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(audit.clone())), material_roots: Arc::new(vec![]),
            account_authority: rss_mdm_apple_channel::account_enrollment::authority(), authentication: rss_mdm_apple_channel::account_enrollment::Authentication {authority: identity.authority.clone(), http: identity.browser().http.clone(), origin: "https://mdm.example.test".into()},
            mount: crate::device::ChannelMount::new(tenant, rss_mdm_inventory::ReportSource::MdmApple, rss_mdm_registration_service::Purpose::Primary),
            audit_store: audit.clone(), access: Arc::new(rss_mdm_apple_channel::Store::from_pool(pool.clone(), registration.clone(), authorization.clone())), apple: Some(apple.channel.clone()),
            clock: Arc::new(crate::clock::InventoryClock(clock.clone())), execution: execution.service.clone(), protection: execution.protection.clone(), credentials: credentials.clone(), devices: devices.clone(), identity: sessions.clone(), requests: requests.clone(),
        });
        identity.enterprise_platform.bind(execution.service.clone())?;
        if let Some(platform) = &identity.platform { platform.bind(&ade)?; }
        let content_access = Arc::new(rss_mdm_content_service::service::Access {
            sessions: rss_mdm_authorization_service::session::SessionAuthority::new(identity.authority.clone(), tenant), authorization: authorization.clone(), runtime: plan_runtime.clone(),
            audit_store: plan_audit.clone(), tenant, content: execution.content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())), catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
        });
        let software = Arc::new(rss_mdm_software_service::management::catalog::Access {
            cursor: rss_mdm_query::cursor::CursorCodec::new(&key)?, resources: Arc::new(rss_mdm_resource_postgres::ResourceStore::new(plan_runtime.clone(), tenant, crate::identity::deadline()).await?),
            clock: Arc::new(crate::clock::ContentClock(clock.clone())), runtime: plan_runtime.clone(), audit: plan_audit.clone(), tenant,
            catalog: rss_mdm_software_service::catalog::Catalog::new(plan_runtime.clone(), tenant, plan_audit.clone()),
            content: execution.content.as_ref().map(|store| Arc::new(rss_mdm_content_service::software::SoftwareContent::new(store.clone(), Arc::new(crate::clock::ContentClock(clock.clone()))))),
            imports: rss_mdm_software_service::management::catalog::ImportConfig {sources: execution.content.as_ref().map(|s| s.config.imports.clone()).unwrap_or_default(), transfer_seconds: execution.content.as_ref().map_or(0, |s| s.config.transfer_seconds)},
        });
        let channels = Arc::new(crate::registration_channels::Channels {preparation: execution.channels.clone(), windows: None, agent: agent_pki.clone(), apple: Some(apple.clone()), pki: pki.clone(), clock: clock.clone()});
        let enrollment = Arc::new(crate::enrollment::http::HttpState {
            channels, native: Arc::new(crate::enrollment_progress::EnrollmentProgress {sessions: sessions.clone(), windows: None, apple: Some(apple.channel.clone())}),
            service: Arc::new(crate::enrollment::EnrollmentService::new(registration.clone(), credentials.clone(), audit.clone())), devices: devices.clone(), windows: false, apple: true,
        });
        let cursor = rss_mdm_query::cursor::CursorCodec::new(&key)?;
        let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState {planning: planning.clone(), groups}))
            .merge(rss_mdm_management_http::planning::policies::http::routes(execution.queries.clone()).with_state(policies))
            .merge(rss_mdm_management_http::planning::policies::http::previews(execution.queries.clone(), None))
            .merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState {catalog, content: content_access.clone()})))
            .merge(rss_mdm_management_http::assets::routes().with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState {assets: assets.clone()})))
            .merge(rss_mdm_management_http::compliance::http::routes().with_state(compliance.clone()))
            .merge(rss_mdm_management_http::content::http::routes().with_state(content_access))
            .merge(rss_mdm_management_http::software_catalog::routes().with_state(software.clone()))
            .merge(rss_mdm_management_http::execution::routes(execution.queries.clone(), cursor.clone()).with_state(Arc::new(rss_mdm_management_http::execution::http::HttpState {execution: execution.service.clone(), windows: false, apple: true})))
            .merge(rss_mdm_management_http::enrollment::http::routes().with_state(enrollment))
            .merge(rss_mdm_management_http::enrollment::directory::routes().with_state(Arc::new(rss_mdm_management_http::enrollment::directory::HttpState {cursor, devices: devices.clone(), assets: assets.clone(), queries: execution.queries.clone(), windows: false, apple: true})))
            .merge(rss_mdm_management_http::agent_enrollment::routes(agent_enrollment.clone()));
        let routes = routes.merge(rss_mdm_management_http::device_views::routes(sessions.clone(), identity.authority.clone(), platform_configuration.clone()).with_state(associations.clone()))
            .merge(rss_mdm_management_http::recovery_credentials::routes(execution.service.recovery_credentials().map(|p| Arc::new(rss_mdm_recovery_credentials::Credentials::new(pool.clone(), audit.clone(), p.keys.clone(), Some(access_audit.clone()), execution.service.clone()))), rss_mdm_query::cursor::CursorCodec::new(&key)?));
        let protected = Router::new().nest("/api/v1", routes.into_axum()).merge(authority.authorization())
            .merge(rss_mdm_apple_channel::management_routes(ade.clone()).into_axum().layer(axum::middleware::from_fn(crate::api::apple_management_settlement)));
        let boundary = rss_mdm_apple_channel::boundary::Envelope {admission: Arc::new(tokio::sync::Semaphore::new(32)), host: "mdm.example.test".into(), clock: monotonic.clone(), audit_store: audit.clone(), requests: requests.clone(), tenant: tenant.to_string()};
        let protected = protected.merge(rss_mdm_management_http::enterprise_broker::routes(agent_enrollment.clone(), execution.service.clone(), identity.browser(), "mdm.example.test", serde_json::to_value(&platform_configuration)?).into_axum());
        let authentication = rss_mdm_management_http::authentication_routes(rss_mdm_http_contract::Router::from_identity_router(identity.routes()),
            rss_mdm_management_http::boundary::Envelope {admission: Arc::new(tokio::sync::Semaphore::new(32)), host: "mdm.example.test".into(), clock: monotonic.clone(), audit_store: audit.clone(), requests: requests.clone(), tenant: tenant.to_string()}).into_axum();
        let mut router = authority.protect(protected)?.merge(rss_mdm_apple_channel::browser_routes(ade.clone(), boundary.clone()).into_axum()).merge(authentication);
        let native = crate::apple::router(Some(&apple), ade.clone(), monotonic.clone()).context("Apple listener")?;
        let mut agent_channel = None;
        if let Some(service) = &agent_enrollment {
            let envelope = rss_mdm_agent_channel::boundary::Envelope {admission: Arc::new(tokio::sync::Semaphore::new(32)), host: String::new(), clock: monotonic.clone(), audit_store: audit.clone(), requests: requests.clone(), tenant: tenant.to_string()};
            let agent = rss_mdm_agent_channel::router(Arc::new(crate::agent::HttpState {content: execution.content.clone(), enrollment: service.clone(), audit_store: audit.clone(), access: Arc::new(rss_mdm_agent_channel::Store::from_pool(pool.clone())), inventory: runtime.clone(), telemetry: None}), envelope.clone())
                .merge(rss_mdm_agent_channel::task_router(Arc::new(crate::agent::TaskState {identity: sessions, authorization, enrollment: service.clone(), access: Arc::new(rss_mdm_agent_channel::Store::from_pool(pool.clone())), execution: execution.service.clone()}), envelope.clone()));
            let agent = agent.merge(rss_mdm_agent_channel::boundary::wrap(rss_mdm_apple_channel::platform_sso::agent_routes(ade.clone(), service.clone()), envelope.clone()));
            let agent = rss_mdm_http_contract::Router::new().nest("/api/v1/agent/runtime", agent).nest("/api/v1/agent/enroll", rss_mdm_agent_channel::enroll::router(service.clone(), envelope.clone())
                .merge(rss_mdm_agent_channel::installation_router(execution.service.clone(), envelope.clone()))
                .merge(rss_mdm_agent_channel::boundary::wrap_enroll(rss_mdm_management_http::software_catalog::agent_packages_public(software), envelope)));
            let channel = crate::native::ChannelRouter {origins: agent_pki.as_ref().unwrap().origins.clone(), router: agent.into_axum(), admission: crate::native::admission::Admission::new(monotonic.clone(), requests.clone(), "agent-tls")};
            router = crate::test_support::gateway::browser_agent(router, channel.router.clone(), "mdm.example.test");
            agent_channel = Some(channel);
        }
        let hook_origin = format!("https://mdm.example.test:{}", webhook.local_addr()?.port());
        let endpoint = crate::native::PublicEndpoint {
            origin: hook_origin.clone(),
        };
        let hooks = rss_mdm_apple_channel::browser_routes(ade.clone(), rss_mdm_apple_channel::boundary::Envelope {host: hook_origin.trim_start_matches("https://").into(), ..boundary}).into_axum();
        let lose_notify = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failure = lose_notify.clone();
        let pause_before_notify = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pause = pause_before_notify.clone();
        let notify_tenant = case_tenant().to_owned();
        let hooks = hooks.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let failure = failure.clone();
                let pause = pause.clone();
                let tenant = notify_tenant.clone();
                async move {
                    use axum::response::IntoResponse;
                    if request.uri().path() == "/api/v1/apple/scep/notify"
                        && failure.load(std::sync::atomic::Ordering::SeqCst)
                    {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    if request.uri().path() == "/api/v1/apple/scep/notify"
                        && pause.swap(false, std::sync::atomic::Ordering::SeqCst)
                    {
                        let result = async {
                            use sqlx::Connection;
                            let mut pg = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
                            sqlx::query("INSERT INTO mdm_access.registration_admission(tenant_id,channel,revision,paused) VALUES($1::uuid,'macos_mdm',1,true)")
                                .bind(&tenant).execute(&mut pg).await?;
                            pg.close().await?;
                            anyhow::Ok(())
                        }.await;
                        if result.is_err() { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
                    }
                    next.run(request).await
                }
            },
        ));
        let hooks = native::ChannelRouter {
            admission: native::admission::Admission::new(
                monotonic,
                requests.clone(),
                "apple-webhook-fixture",
            ),
            origins: vec![endpoint.origin.clone()],
            router: hooks.layer(axum::middleware::from_fn(native::admission::admit)),
        };
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(40))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let notifications = crate::worker_wake::Listener::new(
            crate::device::test_support::options("mdm_access")?,
            rss_request_context::TenantId::parse(case_tenant())?,
        );
        let signals = notifications.signals.clone();
        {
            let mut startup = owner.startup()?;
            startup.stage_resource(rss_runtime::DynManagedResource::new_box(
                notifications.clone(),
            ));
            let mut launch = startup.commit();
            launch.stage_task_with_token(notifications.registration().critical());
            launch.stage_task_with_token(
                crate::test_support::gateway::registration(manage, native, crate::native::ChannelKind::AppleManagement).await?
                .critical(),
            );
            launch.stage_task_with_token(
                crate::test_support::gateway::registration(webhook, hooks, crate::native::ChannelKind::AppleWebhookFixture).await?
                .critical(),
            );

            launch.stage_deferred_task_with_token(
                runtime.clone()
                    .registration(signals.handle(crate::worker_wake::Work::Inventory))
                    .critical(),
            );
            launch.finish();
        }
        let mut execution_owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = execution_owner.startup()?.commit();
        launch.stage_deferred_task_with_token(execution.service.clone().registration(signals.execution()).critical());
        launch.finish();
        if !preserve_authorization {
            crate::test_support::identity::seed_grants(
                case_tenant(),
                crate::test_support::case::admin(),
                crate::test_support::identity::device_grants(
                    Some(case_device()),
                    &[
                        "enrollment",
                        "credentials",
                        "inventory_read",
                        "inventory_collect",
                        "configuration_write",
                        "operation_read",
                        "operation_cancel",
                    ],
                )?,
            )
            .await?;
        }
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
        let browser = crate::test_support::authority::Authority::prepared_browser("admin")?;
        Ok(Self {
            resources: Default::default(),
            authority, commands: execution, planning, assets, compliance, apple, devices, associations, clock, inventory: runtime, requests, agent_enrollment, agent_channel,
            browser,
            router,
            owner: Some(owner),
            execution_owner: Some(execution_owner),
            signals,
            root,
            lose_notify,
            pause_before_notify,
            ade,
        })

        })).await?;
        fixture.resources = resources;
        Ok(fixture)
    }
    async fn profile_query_due(&self, operation: Uuid) -> Result<()> {
        use sqlx::Connection;
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(case_tenant())
            .execute(&mut pg)
            .await?;
        // Advance only the durable read retry clock; request, receipt and eligibility remain intact.
        let count = sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp() WHERE tenant_id=$1::uuid AND operation=$2 AND phase='observe'")
            .bind(case_tenant()).bind(operation).execute(&mut pg).await?.rows_affected();
        ensure!(count > 0);
        pg.close().await?;
        Ok(())
    }
    fn native_grants(extra: &[&str]) -> Result<Vec<crate::authorization::Grant>> {
        let mut operations = vec![
            "enrollment",
            "credentials",
            "inventory_read",
            "inventory_collect",
            "configuration_write",
            "operation_read",
            "operation_cancel",
        ];
        operations.extend_from_slice(extra);
        crate::test_support::identity::device_grants(Some(case_device()), &operations)
    }
    async fn enrollment(&mut self) -> Result<(Uuid, Uuid, String)> {
        self.enrollment_source(false).await
    }
    async fn self_enrollment(&mut self) -> Result<(Uuid, Uuid, String)> {
        self.enrollment_source(true).await
    }
    async fn enrollment_source(&mut self, self_service: bool) -> Result<(Uuid, Uuid, String)> {
        let password = crate::enrollment::random();
        let mut browser = if self_service {
            let proof = crate::device::test_support::admin(case_tenant(), "other-a").await?;
            crate::test_support::identity::seed_grants(case_tenant(), proof.principal_id(), vec![])
                .await?;
            let secret =
                crate::test_support::identity::credential(&self.authority.identity, "other")?;
            Browser {
                cookies: std::collections::BTreeMap::from([(
                    "__Host-identity-session".into(),
                    secret.expose().into(),
                )]),
                csrf: Some(secret.csrf()),
                ..Default::default()
            }
        } else {
            self.browser.clone()
        };
        browser.network = self.browser.network.clone();
        browser.operation = Some(Uuid::new_v4());
        let mut input = json!({"source":"mdm.apple","password":password});
        if !self_service {
            input["deviceId"] = json!(case_device());
        }
        let reply = browser
            .call(
                &self.router,
                Method::POST,
                if self_service {
                    "/api/v1/self-enrollments"
                } else {
                    "/api/v1/enrollments"
                },
                Some(input),
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK, "Apple enrollment {reply:?}");
        self.browser.operation = None;
        let enrollment = Uuid::parse_str(reply.1["enrollmentId"].as_str().unwrap())?;
        self.profile_request(enrollment, password).await
    }
    async fn profile_request(
        &mut self,
        enrollment: Uuid,
        password: String,
    ) -> Result<(Uuid, Uuid, String)> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/enrollments/{enrollment}/profile"))
            .header("host", "mdm.example.test")
            .header("content-type", "application/json")
            .body(Body::from(json!({"password":password}).to_string()))?;
        let body = if let Some((client, origin)) = &self.browser.network {
            let response = client
                .post(format!("{origin}/api/v1/enrollments/{enrollment}/profile"))
                .header("host", "mdm.example.test")
                .json(&json!({"password":password}))
                .send()
                .await?;
            ensure!(
                response.status() == StatusCode::OK,
                "HTTPS profile {}",
                response.status()
            );
            response.bytes().await?
        } else {
            let response = self.router.clone().oneshot(request).await?;
            ensure!(
                response.status() == StatusCode::OK,
                "Apple profile download {}",
                response.status()
            );
            axum::body::to_bytes(response.into_body(), 1024 * 1024).await?
        };
        use x509_cert::der::{Decode, asn1::OctetString};
        let cms = cms::content_info::ContentInfo::from_der(&body)?
            .content
            .decode_as::<cms::signed_data::SignedData>()?;
        let bytes = cms
            .encap_content_info
            .econtent
            .unwrap()
            .decode_as::<OctetString>()?;
        let d = protocol::decode(bytes.as_bytes())?;
        let contents = d["PayloadContent"].as_array().unwrap();
        let scep = contents[0].as_dictionary().unwrap();
        let attempt = Uuid::parse_str(scep["PayloadUUID"].as_string().unwrap())?;
        ensure!(
            scep["PayloadContent"].as_dictionary().unwrap()["Challenge"].as_string()
                == Some(password.as_str())
        );
        Ok((enrollment, attempt, password))
    }
    async fn https_browser(&self) -> Result<(reqwest::Client, String, rss_runtime::ShutdownStack)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = crate::native::PublicEndpoint {
            origin: "https://mdm.example.test".into(),
        };
        let origin = format!("https://localhost:{}", listener.local_addr()?.port());
        let router = native::ChannelRouter {
            origins: vec![endpoint.origin.clone()],
            router: self.router.clone(),
            admission: native::admission::Admission::new(
                fixture_clock(),
                self.requests.clone(),
                "self-enrollment-browser",
            ),
        };
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut startup = owner.startup()?.commit();
        startup.stage_task_with_token(
            crate::test_support::gateway::registration(
                listener,
                router,
                native::ChannelKind::AppleWebhookFixture,
            )
            .await?
            .critical(),
        );
        startup.finish();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                self.root.join("ca.crt"),
            )?)?)
            .build()?;
        Ok((client, origin, owner))
    }
    async fn self_progress(&self, enrollment: Uuid) -> Result<serde_json::Value> {
        let secret = crate::test_support::identity::credential(&self.authority.identity, "other")?;
        let mut browser = Browser {
            network: self.browser.network.clone(),
            cookies: std::collections::BTreeMap::from([(
                "__Host-identity-session".into(),
                secret.expose().into(),
            )]),
            ..Default::default()
        };
        let (status, value) = browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v1/enrollments/{enrollment}"),
                None,
            )
            .await?;
        ensure!(status == StatusCode::OK, "progress {status} {value}");
        Ok(value)
    }
    fn client(&self) -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                std::env::var("MDM_STEP_CA_ROOT")?,
            )?)?)
            .build()?)
    }
}

#[allow(clippy::disallowed_methods, reason = "test composition root")]
fn fixture_clock() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(std::time::Instant::now))
}

fn startup_diagnostics(root: &std::path::Path) -> Result<()> {
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
    for (pointer, category) in [
        ("/trust_file", "FileAccess"),
        ("/webhooks/0/challenge/secret_file", "AppleChallengeWebhook"),
        ("/webhooks/0/notify/secret_file", "AppleNotifyWebhook"),
    ] {
        let mut input = original.clone();
        *input.pointer_mut(pointer).unwrap() = json!("private-material-path-must-not-be-logged");
        let config = serde_json::from_value(input)?;
        match Apple::load(
            crate::test_support::identity::config(case_tenant())?.native_protector()?,
            config,
            fixture_materials(root)?,
            crate::clock::SystemClock.unix_seconds()?,
            (
                "https://mdm.example.test",
                rss_request_context::TenantId::parse(case_tenant())?,
            ),
            fixture_providers(root)?,
        ) {
            Err(crate::Error::Configuration(issue)) => ensure!(
                format!("{issue:?}") == category,
                "wrong startup category for {pointer}"
            ),
            _ => anyhow::bail!("missing startup category for {pointer}"),
        }
    }
    let apple = Apple::load(
        crate::test_support::identity::config(case_tenant())?.native_protector()?,
        serde_json::from_value(original)?,
        fixture_materials(root)?,
        crate::clock::SystemClock.unix_seconds()?,
        (
            "https://mdm.example.test",
            rss_request_context::TenantId::parse(case_tenant())?,
        ),
        fixture_providers(root)?,
    )?;
    ensure!(
        apple
            .channel
            .health(crate::clock::SystemClock.unix_seconds()?)
            .is_ready()
    );
    Ok(())
}

mod collection;
mod fairness;
#[path = "production.rs"]
mod host;
mod identity;
mod profile;
#[path = "push_cycle.rs"]
mod push;
#[path = "renewal.rs"]
mod renewal;

impl Fixture {
    async fn stop_execution_worker(&mut self) -> Result<()> {
        crate::test_support::runtime::stop_worker(self.execution_owner.take()).await
    }
    async fn close(self) -> Result<()> {
        let Self {
            resources,
            owner,
            execution_owner,
            inventory,
            ..
        } = self;
        resources
            .finish(async move {
                let report = match owner {
                    Some(owner) => Some(owner.shutdown().join().await?),
                    None => None,
                };
                crate::test_support::runtime::stop_worker(execution_owner).await?;
                if report.as_ref().is_some_and(|report| !report.is_clean()) {
                    let diagnostics = inventory
                        .diagnostics(fixture_clock().now() + Duration::from_secs(1))
                        .await;
                    if let Some(rss_projection::ObservationStatus::Stopped(projection)) =
                        diagnostics.projection
                        && let rss_projection::Stop::Failed(error) = projection.stop
                    {
                        let detail = error.diagnostic();
                        eprintln!(
                            "{}",
                            json!({
                                "event": "apple_fixture_inventory_projection_failure",
                                "kind": format!("{:?}", error.kind()),
                                "providerPhase": detail.map(|d| format!("{:?}", d.phase())),
                                "sqlstate": detail.and_then(|d| d.sqlstate()),
                                "position": detail.and_then(|d| d.position()).map(|p| p.get()),
                            })
                        );
                    }
                }
                ensure!(
                    report.as_ref().is_none_or(|report| report.is_clean()),
                    "Apple fixture shutdown: {report:?}"
                );
                Ok(())
            })
            .await
    }

    fn peer_identity(&self, device: &scep_client::Device, der: &[u8]) -> Result<lifecycle::Peer> {
        let apple = self.apple.as_ref();
        let peer = lifecycle::Peer {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(40))
                .identity(device.identity(der)?)
                .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                    self.root.join("ca.crt"),
                )?)?)
                .build()?,
            pending_replies: Default::default(),
            installed_trust: Default::default(),
            oracle: oracle::Oracle::new(der)?,
            origin: apple.config.management.origin.clone(),
            topic: apple.channel.apns_topic().to_owned(),
        };
        Ok(peer)
    }
    async fn authenticate_peer(
        &self,
        device: &scep_client::Device,
        der: &[u8],
    ) -> Result<lifecycle::Peer> {
        let peer = self.peer_identity(device, der)?;
        let reply = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "Authenticate".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("Topic", peer.topic.clone().into()),
                ]),
            )
            .await?;
        ensure!(
            reply.0 == StatusCode::OK,
            "fixture Authenticate: {}",
            reply.0
        );
        Ok(peer)
    }
    async fn seed_local_identity(&self) -> Result<(scep_client::Device, Vec<u8>)> {
        let device =
            scep_client::Device::new(Uuid::new_v4(), Uuid::new_v4(), &crate::enrollment::random())?;
        let der = device.local_leaf(&std::path::PathBuf::from(std::env::var(
            "MDM_APPLE_PKI_FIXTURES",
        )?))?;
        let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
        let mut tx = self.authority.pool.clone().begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *tx)
            .await?;
        rss_mdm_apple_channel::enrollment::seed_current_peer_in(
            &mut tx,
            &self.apple.as_ref().channel,
            &proof,
            rss_mdm_apple_channel::enrollment::CurrentPeer {
                device: case_device(),
                udid: crate::test_support::case::name("rss-t2-apple"),
                csr: &device.csr,
                certificate: &der,
                now: self.clock.unix_seconds()?,
            },
        )
        .await?;
        tx.commit().await?;
        Ok((device, der))
    }
    async fn ready_local_peer(&mut self) -> Result<(lifecycle::Peer, scep_client::Device)> {
        let (device, der) = self.seed_local_identity().await?;
        let peer = self.authenticate_peer(&device, &der).await?;
        peer.token().await?;
        // Complete the independent trust exchange before tests publish their policies.
        // Otherwise its extra signed check-ins can dispatch a run during queue preparation.
        let reply = peer.manage("Idle", None, None).await?;
        if !reply.is_empty() {
            peer.pending_replies.lock().await.push_back(reply);
        }
        Ok((peer, device))
    }
}

impl Fixture {
    /// Publish ordinary tenant Resource/Scope through the same HTTP owners used by administrators.
    pub(super) async fn collection_template(&mut self) -> Result<serde_json::Value> {
        self.collection_template_scoped(rss_mdm_resource::TemplateScope::Device)
            .await
    }
    pub(super) async fn collection_template_scoped(
        &mut self,
        scope: rss_mdm_resource::TemplateScope,
    ) -> Result<serde_json::Value> {
        use crate::test_support::agent_execution::upload;
        use rss_mdm_resource::{
            NativeAdapter, NativeCollectionDefinition, NativeCollectionSpec, NativeMapping,
        };
        let template = NativeCollectionDefinition::new(NativeCollectionSpec {
            scope,
            applicability: Default::default(),
            adapter: NativeAdapter::AppleDeviceInformation,
            mappings: [
                ("device.model", "Model"),
                ("device.os.version", "OSVersion"),
            ]
            .map(|(field, query)| {
                (
                    field.into(),
                    NativeMapping {
                        query: rss_mdm_resource::NativeQuery::Apple(query.into()),
                        mapping: rss_mdm_agent_wire::runtime::ValueMapping::identity(""),
                    },
                )
            })
            .into(),
            timeout_seconds: 1800,
            output_bytes: 16384,
        })?;
        let bytes = template.canonical();
        let id = Uuid::new_v4();
        crate::test_support::planning_http::seed_native_template(
            &(&self.planning).runtime,
            (&self.planning).tenant,
            id,
            rss_mdm_resource::Platform::MacOS,
            template,
        )
        .await?;
        ensure!(upload(&self.browser, &self.router, id, &bytes).await? == StatusCode::CREATED);
        let scope = Uuid::new_v4();
        crate::test_support::agent_execution::seed_scope(
            &self.planning,
            scope,
            json!([{"kind":"device","id":case_device()}]),
        )
        .await?;
        Ok(
            json!({"scope":scope,"action":{"kind":"native_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":1800}}),
        )
    }

    pub(super) async fn queue_collection(
        &mut self,
        definition: &serde_json::Value,
        peer: &lifecycle::Peer,
    ) -> Result<(Uuid, Uuid)> {
        use sqlx::Connection;
        let policy = Uuid::new_v4();
        self.policy_post(
            &format!("/api/v1/policies/{policy}"),
            0,
            json!({"action":"put","enabled":true,"definition":definition}),
        )
        .await?;
        let reply = peer.manage("Idle", None, None).await?;
        if !reply.is_empty() {
            peer.pending_replies.lock().await.push_back(reply);
        }
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let run = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let run: Option<Uuid> = sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_access.collection_runs c ON(c.tenant_id,c.id)=(r.tenant_id,r.id) JOIN mdm_apple.attempts a ON(a.tenant_id,a.collection)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.gateway_accepted AND c.sealed_at IS NULL AND a.phase='collect_device'")
                    .bind(case_tenant()).bind(policy).fetch_optional(&mut db).await?;
                if let Some(run) = run { return Ok::<_, anyhow::Error>(run); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await??;
        db.close().await?;
        Ok((policy, run))
    }

    pub(super) async fn pending_collections(
        &mut self,
        definition: &serde_json::Value,
        count: usize,
        peer: &lifecycle::Peer,
    ) -> Result<Vec<Uuid>> {
        use sqlx::Connection;
        ensure!(count > 0);
        // One frozen Policy version owns distinct pending occurrences. Queue through
        // the production owner so fingerprints, outbox and source evidence stay real.
        let (_, first) = self.queue_collection(definition, peer).await?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let (version, registration, generation): (Uuid, Uuid, i64) = sqlx::query_as(
            "SELECT policy_version,registration,generation FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(first).fetch_one(&mut db).await?;
        let mut runs = vec![first];
        runs.extend((1..count).map(|_| Uuid::new_v4()));
        if count > 1 {
            let target = rss_mdm_execution_service::Target {
                device: case_device().into(),
                registration,
                generation,
            };
            let pending = runs[1..].to_vec();
            let now = self.clock.unix_seconds()?;
            self.commands.runtime.local_tx_with_context(
                rss_request_context::TenantId::parse(case_tenant())?,
                // Only preparation is batched; the worker recovers each run in its own production transaction.
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(30)),
                &self.commands.service, |service, tx| Box::pin(async move {
                    let partitions=pending.iter().map(|id|rss_mdm_audit_integration::source_partition(tx.tenant_id(),"mdm",&id.to_string())).collect::<std::result::Result<Vec<_>,_>>().map_err(|e|rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                    tx.prepare_outbox_partitions(&partitions).await?;
                    for id in pending {
                        rss_mdm_execution_service::actions::production::queue_run_in(service, tx,
                            rss_mdm_execution_service::actions::production::RunInput {
                                triggered_at: Some(now),
                                source: rss_mdm_execution_service::actions::storage::Source::Policy { version },
                                target: &target, id, occurrence: format!("backlog:{id}"),
                                available: now, deadline: now + 1800, now,
                            }).await.map_err(|e| rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                    }
                    Ok(())
                }),
            ).await.fold(Ok, |e| Err(anyhow::anyhow!(e)), |e| Err(anyhow::anyhow!(e)),
                |_| Err(anyhow::anyhow!("backlog preparation rollback unconfirmed")),
                |_| Err(anyhow::anyhow!("backlog preparation commit unconfirmed")), |e| Err(anyhow::anyhow!(e)))?;
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let accepted: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=ANY($2) AND gateway_accepted AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'='none'")
                    .bind(case_tenant()).bind(&runs).fetch_one(&mut db).await?;
                if accepted == count as i64 { return Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await??;
        // The full live workset must reach the protocol owner through the real worker.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
        let pending: i64 = sqlx::query_scalar("SELECT count(DISTINCT c.id) FROM mdm_commands.action_runs r JOIN mdm_access.collection_runs c USING(tenant_id,id) JOIN mdm_apple.attempts a ON(a.tenant_id,a.collection)=(c.tenant_id,c.id) WHERE c.tenant_id=$1::uuid AND c.id=ANY($2) AND c.sealed_at IS NULL AND a.phase='collect_device' AND a.state='pending' AND r.gateway_accepted AND r.state->>'execution' IN ('not_started','running') AND r.state->>'cancellation'='none'")
            .bind(case_tenant()).bind(&runs).fetch_one(&mut db).await?;
                if pending == count as i64 { return Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.map_err(|_| anyhow::anyhow!("recovery did not preserve the entire live backlog"))??;
        db.close().await?;
        Ok(runs)
    }
}

fn native_profile() -> &'static str {
    crate::test_support::case::name("org.example.native-profile")
}
fn profile_task(id: Uuid, enabled: bool) -> serde_json::Value {
    json!({"platform":"macos","request":{"kind":"install_profile","profile":{"identifier":native_profile(),"uuid":id,"metadata":{},"payloads":[{"schema":"mdm/profiles/com.apple.security.firewall.yaml","identifier":format!("{}.settings",native_profile()),"uuid":Uuid::from_u128(id.as_u128() ^ (1<<127)),"metadata":{},"fields":{"EnableFirewall":{"type":"boolean","value":enabled}}}]}}})
}
fn remove_profile_task(profile: Uuid) -> serde_json::Value {
    json!({"platform":"macos","request":{"kind":"remove_profile","identifier":native_profile(),"uuid":profile}})
}

fn profile_manifest(id: Uuid, kind: &str) -> plist::Value {
    plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
        ("PayloadIdentifier", native_profile().into()),
        ("PayloadUUID", id.to_string().into()),
        ("PayloadVersion", 1.into()),
        (
            "PayloadContent",
            plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
                (
                    "PayloadIdentifier",
                    format!("{}.settings", native_profile()).into(),
                ),
                (
                    "PayloadUUID",
                    Uuid::from_u128(id.as_u128() ^ (1 << 127))
                        .to_string()
                        .into(),
                ),
                ("PayloadType", kind.into()),
                ("PayloadVersion", 1.into()),
            ]))]),
        ),
    ]))])
}

// The listener remains owned throughout the control-plane update and TLS startup.
// ref: smallstep/cli v0.30.2 command/ca/provisioner/webhook/update.go.
async fn publish_webhooks(address: std::net::SocketAddr) -> Result<()> {
    let root = std::path::PathBuf::from(std::env::var("MDM_APPLE_PKI_FIXTURES")?);
    use std::io::Write;
    use tokio::io::AsyncReadExt;
    let mut diagnostics = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("step-webhooks.log"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        diagnostics.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    for (name, phase) in [("rss", "challenge"), ("rss_notify", "notify")] {
        let mut child = tokio::process::Command::new(std::env::var("MDM_STEP_CLI")?)
            .args([
                "ca",
                "provisioner",
                "webhook",
                "update",
                "rss",
                name,
                "--url",
            ])
            .arg(format!(
                "https://mdm.example.test:{}/api/v1/apple/scep/{phase}",
                address.port()
            ))
            .arg("--ca-url")
            .arg(std::env::var("MDM_STEP_CA_URL")?)
            .arg("--root")
            .arg(std::env::var("MDM_STEP_CA_ROOT")?)
            .args([
                "--admin-subject",
                "rss-admin",
                "--admin-provisioner",
                "rss-admin",
                "--admin-password-file",
            ])
            .arg(root.join("step-password"))
            .env("STEPPATH", root.join("step"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stderr = child.stderr.take().unwrap();
        let mut evidence = Vec::new();
        let completion = tokio::time::timeout(Duration::from_secs(30), async {
            stderr.take(64 * 1024).read_to_end(&mut evidence).await?;
            child.wait().await
        })
        .await;
        let status: Result<_> = match completion {
            Ok(result) => result.map_err(Into::into),
            Err(_) => {
                child.kill().await?;
                child.wait().await?;
                Err(anyhow::anyhow!(
                    "Apple {phase} webhook publication deadline"
                ))
            }
        };
        writeln!(diagnostics, "[{phase}]")?;
        diagnostics.write_all(&evidence)?;
        let status = status?;
        ensure!(
            status.success(),
            "Apple {phase} webhook publication failed: {status}"
        );
    }
    Ok(())
}

fn fixture_providers(
    root: &std::path::Path,
) -> Result<Arc<rss_mdm_pki_service::providers::Providers>> {
    let providers: Vec<crate::device_pki::Provider> =
        serde_json::from_slice(&std::fs::read(root.join("device-pki.json"))?)?;
    Ok(crate::device_pki::providers(&providers)?)
}

#[derive(serde::Deserialize)]
pub(in crate::apple) struct FixtureMaterials {
    pub(in crate::apple) profile_certificate_file: PathBuf,
    pub(in crate::apple) profile_private_key_file: PathBuf,
    pub(in crate::apple) apns_certificate_file: PathBuf,
    pub(in crate::apple) apns_private_key_file: PathBuf,
    pub(in crate::apple) apns_topic: String,
}
fn fixture_materials(
    root: &std::path::Path,
) -> Result<rss_mdm_apple_channel::runtime_materials::runtime::Loaded> {
    let input: FixtureMaterials =
        serde_json::from_slice(&std::fs::read(root.join("apple-materials.json"))?)?;
    let certificate = std::fs::read(input.profile_certificate_file)?;
    let private = zeroize::Zeroizing::new(std::fs::read(input.profile_private_key_file)?);
    let now = crate::clock::SystemClock.unix_seconds()?;
    Ok(rss_mdm_apple_channel::runtime_materials::runtime::Loaded {
        binding: rss_mdm_apple_channel::runtime_materials::runtime::Binding::fixture(now + 3600),
        profile: rss_mdm_certificate::apple::ProfileSigner::from_bytes(
            &certificate,
            &private,
            now,
        )?,
        apns_certificate: std::fs::read(input.apns_certificate_file)?,
        apns_private_key: zeroize::Zeroizing::new(std::fs::read(input.apns_private_key_file)?),
        apns_topic: input.apns_topic,
        accounts: std::collections::BTreeMap::from([(
            "organization".into(),
            rss_mdm_certificate::apple::ManagedAccountTokenSigner::from_bytes(
                &certificate,
                &private,
                now,
            )?,
        )]),
    })
}

/// Seed the durable owner used by the real host startup test. These rows are fixture data;
/// production startup has no fixture/file import branch.
async fn seed_fixture_materials(
    root: &std::path::Path,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<()> {
    use rss_mdm_native_protection::ProtectionContext;
    use sha2::{Digest, Sha256};
    use sqlx::Connection;
    use x509_cert::der::{DecodePem, Encode};
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?)
            .await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    for (purpose, name, topic) in [
        ("apns", "apple-apns", Some("com.apple.mgmt.rss-t2")),
        ("profile", "apple-profile", None),
        ("managed_account", "apple-profile", None),
    ] {
        let key_id = uuid::Uuid::new_v4();
        let private = zeroize::Zeroizing::new(std::fs::read(root.join(format!("{name}.pk8")))?);
        let pem = std::fs::read_to_string(root.join(format!("{name}.pem")))?;
        let cert = x509_cert::Certificate::from_pem(&pem)?;
        let der = cert.to_der()?;
        let mut digest = Sha256::new();
        digest.update((der.len() as u64).to_be_bytes());
        digest.update(&der);
        let public_digest = format!(
            "{:x}",
            Sha256::digest(cert.tbs_certificate.subject_public_key_info.to_der()?)
        );
        let aad = ProtectionContext::new(
            rss_request_context::TenantId::parse(case_tenant())?,
            &format!("{purpose}:1:{key_id}"),
            "apple.runtime.private-key",
            1,
        )?
        .derive();
        let sealed = protection.seal_bytes(&private, &aad)?;
        let expires = cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64;
        sqlx::query("INSERT INTO mdm_apple_runtime.heads(tenant_id,purpose,revision,desired_revision) VALUES($1::uuid,$2,1,1) ON CONFLICT DO NOTHING").bind(case_tenant()).bind(purpose).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_apple_runtime.versions(tenant_id,purpose,revision,key_id,public_digest,private_key,csr,certificate,certificate_digest,topic,expires_at,selected) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,true) ON CONFLICT DO NOTHING")
            .bind(case_tenant()).bind(purpose).bind(key_id).bind(public_digest).bind(sealed).bind(std::fs::read_to_string(root.join(format!("{name}.csr")))?).bind(pem).bind(format!("{:x}",digest.finalize())).bind(topic).bind(expires).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
