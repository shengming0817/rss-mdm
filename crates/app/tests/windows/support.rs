use super::*;
use crate::api::Assembly;
use crate::enrollment::test_support::audit;
use crate::{
    Database,
    device::test_support::{admin, options},
    enrollment::{Authorization, Password},
};
use crate::{authorization::context::AuthorizedPrincipal, clock::Clock};
use anyhow::ensure;
use axum::Router;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_identity_core::{entra::EntraTokenProfile, federation::*};
use rss_mdm_windows_mdm::syncml::{self, Command, CommandName};
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
};
use std::collections::BTreeMap;
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;
use x509_cert::der::Decode;
pub(crate) fn case_tenant() -> &'static str {
    crate::test_support::case::tenant()
}
pub(crate) fn root() -> anyhow::Result<PathBuf> {
    Ok(std::env::var("MDM_WINDOWS_FIXTURES")?.into())
}
pub(crate) fn now() -> i64 {
    crate::clock::SystemClock.unix_seconds().unwrap()
}
pub(super) fn windows() -> anyhow::Result<Windows> {
    let config = serde_json::from_slice(&std::fs::read(root()?.join("windows.json"))?)?;
    Ok(Windows::load(config, now(), fixture_providers()?, None)?)
}
pub(super) async fn complete(
    store: &rss_mdm_audit_integration::AuditStore,
    w: &Windows,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
    intent: &issuance::Intent,
    cert: &[u8],
) -> Result<(), Error> {
    let a = audit(proof, auth.operation, &auth.device, "enrollment_issue");
    let result = rss_mdm_windows_channel::issuance::complete_issuance(
        store,
        &w.channel,
        auth,
        proof,
        intent,
        cert,
        &a,
        now(),
        &crate::device::ChannelMount::new(
            rss_request_context::TenantId::parse(proof.tenant_id()).unwrap(),
            rss_mdm_inventory::ReportSource::MdmWindows,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        &crate::registration_lifecycle::Bridge,
    )
    .await;
    a.finalize(None);
    result.map_err(Into::into)
}
#[allow(clippy::disallowed_methods, reason = "test composition root")]
pub(super) fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(std::time::Instant::now))
}
pub(crate) struct IngressClock(std::sync::Mutex<Option<std::time::Instant>>);
impl rss_observation::Clock for IngressClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "T2 ingress clock uses real time until the deterministic burst test"
    )]
    fn now(&self) -> std::time::Instant {
        self.0
            .lock()
            .unwrap()
            .unwrap_or_else(std::time::Instant::now)
    }
}
impl IngressClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "T2 composition root controls only ingress refill time, while TLS/HTTP/PG remain real"
    )]
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(None)))
    }
    pub(crate) fn advance(&self) {
        let now = rss_observation::Clock::now(self);
        *self.0.lock().unwrap() = Some(now + Duration::from_secs(60));
    }
}

async fn admin_session(
    identity: &crate::identity::Identity,
    credential: Option<rss_identity_core::session::SessionSecret>,
) -> anyhow::Result<rss_identity_core::session::SessionSecret> {
    match credential {
        Some(secret) => Ok(secret),
        None => crate::test_support::identity::login(identity, "admin").await,
    }
}

pub(crate) struct Host {
    resources: crate::test_support::runtime::Resources,
    pub(crate) root: PathBuf,
    pub(crate) app: Arc<Assembly>,
    pub(crate) notifications: crate::worker_wake::Listener,
    pub(crate) browser: Router,
    pub(crate) store: Arc<Database>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) ingress_clock: Arc<IngressClock>,
    pub(crate) root_cert: reqwest::Certificate,
    pub(crate) client: reqwest::Client,
    pub(super) secret: rss_identity_core::session::SessionSecret,
    pub(super) reference: Uuid,
    listeners: Vec<(crate::native::ChannelKind, crate::native::ChannelRouter)>,
    enroll: Option<tokio::net::TcpListener>,
    manage: Option<tokio::net::TcpListener>,
    additional_manage: Option<tokio::net::TcpListener>,
    running: Option<rss_runtime::ShutdownStack>,
}
impl Host {
    #[cfg(feature = "integration")]
    pub(crate) async fn with_entra(
        binding: rss_mdm_windows_channel::entra::Config,
        verifier: Arc<dyn rss_identity_core::entra::EntraTokenVerifier>,
        jit: bool,
    ) -> anyhow::Result<Self> {
        Self::bind(
            None,
            rss_device_command_postgres::CommandClock::Postgres,
            None,
            None,
            None,
            false,
            false,
            Some((binding, verifier, jit)),
            false,
        )
        .await
    }
    /// Prepare in-process product routes; listeners and workers start only in listen().
    pub(crate) async fn open() -> anyhow::Result<Self> {
        Self::with_agent(None, rss_device_command_postgres::CommandClock::Postgres).await
    }
    pub(crate) async fn with_agent(
        agent: Option<serde_json::Value>,
        command_clock: rss_device_command_postgres::CommandClock,
    ) -> anyhow::Result<Self> {
        Self::bind(
            agent,
            command_clock,
            None,
            None,
            None,
            false,
            false,
            None,
            false,
        )
        .await
    }
    pub(super) async fn renewal_window() -> anyhow::Result<Self> {
        Self::bind(
            None,
            rss_device_command_postgres::CommandClock::Postgres,
            None,
            None,
            Some("renewal-window"),
            false,
            false,
            None,
            false,
        )
        .await
    }
    pub(super) async fn with_push() -> anyhow::Result<Self> {
        Self::bind(
            None,
            rss_device_command_postgres::CommandClock::Postgres,
            None,
            None,
            None,
            true,
            false,
            None,
            false,
        )
        .await
    }
    pub(crate) async fn with_mdm_software() -> anyhow::Result<Self> {
        Self::bind(
            None,
            rss_device_command_postgres::CommandClock::Postgres,
            None,
            None,
            None,
            false,
            false,
            None,
            true,
        )
        .await
    }
    #[allow(
        clippy::cognitive_complexity,
        clippy::too_many_arguments,
        reason = "fixture composition keeps TLS certificate, listener and enrollment variants explicit"
    )]
    async fn bind(
        agent: Option<serde_json::Value>,
        command_clock: rss_device_command_postgres::CommandClock,
        addresses: Option<(std::net::SocketAddr, std::net::SocketAddr)>,
        credential: Option<rss_identity_core::session::SessionSecret>,
        ca: Option<&str>,
        push: bool,
        additional_address: bool,
        entra: Option<(
            rss_mdm_windows_channel::entra::Config,
            Arc<dyn rss_identity_core::entra::EntraTokenVerifier>,
            bool,
        )>,
        mdm_software: bool,
    ) -> anyhow::Result<Self> {
        let ca = ca.map(str::to_owned);
        let (resources, mut fixture) = crate::test_support::runtime::Resources::build(move |resources| Box::pin(async move {
        let ca = ca.as_deref();
        let root = root()?;
        let enroll =
            tokio::net::TcpListener::bind(addresses.map(|a| a.0).unwrap_or("127.0.0.1:0".parse()?))
                .await?;
        let manage =
            tokio::net::TcpListener::bind(addresses.map(|a| a.1).unwrap_or("127.0.0.1:0".parse()?))
                .await?;
        let additional_manage = if additional_address {
            Some(tokio::net::TcpListener::bind("127.0.0.1:0").await?)
        } else {
            None
        };
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
        value["native_protocols"]["windows"] =
            serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
        value["native_protocols"]["windows"]["enrollment"]["origin"] =
            serde_json::json!(format!("https://localhost:{}", enroll.local_addr()?.port()));
        value["native_protocols"]["windows"]["management"]["origin"] =
            serde_json::json!(format!("https://localhost:{}", manage.local_addr()?.port()));
        let trust_path = root.join(format!("host-trust-{}.json", manage.local_addr()?.port()));
        let mut trust: rss_mdm_agent_wire::pki::Trust = serde_json::from_slice(&std::fs::read(
            value["native_protocols"]["windows"]["trust_file"]
                .as_str()
                .unwrap(),
        )?)?;
        trust.origin = format!("https://localhost:{}", manage.local_addr()?.port());
        std::fs::write(&trust_path, serde_json::to_vec(&trust)?)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&trust_path, std::fs::Permissions::from_mode(0o600))?;
        value["native_protocols"]["windows"]["trust_file"] = serde_json::json!(trust_path);
        value["identity"] = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
            std::env::var("MDM_TEST_CONFIG")?,
        )?)?["identity"]
            .clone();
        value["identity"]["tenant_id"] = serde_json::json!(case_tenant());
        let db: sqlx::postgres::PgConnectOptions = std::env::var("DATABASE_URL")?.parse()?;
        let management_password = root.join("management-password");
        std::fs::write(&management_password, "runtime-fixture")?;
        std::fs::set_permissions(&management_password, std::fs::Permissions::from_mode(0o600))?;
        value["flow"]["storage"]["database"] = serde_json::json!({"host":"localhost","port":db.get_port(),"name":db.get_database().unwrap(),"user":"mdm_flow_runtime","password_file":management_password,"ca_file":root.join("ca.crt")});
        value["execution"]["database"] = value["flow"]["storage"]["database"].clone();
        value["execution"]["database"]["user"] = "mdm_command_runtime".into();
        let _ = agent;
        value["software_distribution"]=serde_json::json!({"mdm_enabled":mdm_software});
        let original: serde_json::Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        value["access_database"] = original["access_database"].clone();
        value["content"] = original["content"].clone();
        value["webhooks"] = original["webhooks"].clone();
        value["agent_pki"] = original["agent_pki"].clone();
        if mdm_software || original["agent_pki"]["mode"] == "step_ca" { value["task_signing"] = original["task_signing"].clone(); }
        value["device_pki"] = original["device_pki"].clone();
        value["native_protection"] = original["native_protection"].clone();
        if push {value["native_protocols"]["windows"]["push"] = serde_json::json!({"revision":1});}
        if let Some(listener) = &additional_manage {
            let mut endpoint = value["native_protocols"]["windows"]["management"].clone();
            endpoint["origin"] = serde_json::json!(format!(
                "https://localhost:{}",
                listener.local_addr()?.port()
            ));
            value["native_protocols"]["windows"]["additional_management"] =
                serde_json::json!([endpoint]);
        }
        let config: crate::config::Config = serde_json::from_value(value)?;
        let clock = Arc::new(crate::clock::SystemClock);
        let identity_management = Arc::new(
            crate::authorization::identity_management::IdentityManagementPolicy::new(
                crate::test_support::identity::INSTANCE,
            )?,
        );
        let identity =
            crate::identity::Identity::connect(&config, identity_management.clone(), Some(crate::apple::identity_platform(&config).await?), |resource| {
                resources.acquire(resource)
            })
            .await?;
        let secret = admin_session(&identity, credential).await?;
        let credentials = crate::enrollment::credentials::Credentials::new(monotonic(), 100);
        let reference = credentials.insert(rss_mdm_authorization_service::credential::RequestCredential::Cookie(rss_identity_core::session::SessionSecret::parse(
            secret.expose().into(),
        )?))?;
        let store = Arc::new(Database::connect(options("mdm_access")?).await?);
        resources.resource(crate::lifecycle::AccessResource(store.clone()));
        let devices = Arc::new(crate::device::DeviceService::new(
            store.registration(),
            case_tenant().into(),
            store
                .audit_store_fixture(&crate::config::AuditConfig::Plain)
                .await?,
        ));
        let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
            options("mdm_runtime")?,
            store.inventory(),
            rss_request_context::TenantId::parse(case_tenant())?,
            monotonic(),
            store
                .audit_store_fixture(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await?;
        resources.resource(crate::test_support::runtime::InventoryFixtureResource(runtime.clone()));
        let (management, timeline) =
            management(&config, &store, runtime.clone(), resources).await?;
        let command_audit = store
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?;
        let content = crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
        if let Some(content) = &content {
            resources.resource(crate::execution_assembly::ContentResource(content.clone()));
        }
        let execution = crate::execution_assembly::open(
            &config,
            config.native_protector()?,
            command_audit.clone(),
            content,
            std::collections::BTreeMap::new(),
            command_clock,
            Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    identity.authority.clone(),
                    identity.tenant,
                ),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("command startup: {e:?}"))?;
        resources.resource(rss_mdm_execution_service::Resource(
            execution.service.clone(),
        ));
        let agent_audit = command_audit.clone();
        let agent_pki = config.agent_pki.load(
            &config.identity.instance_id,
            agent_audit.clone(),
            clock.clone(),
            crate::device_pki::providers(&config.device_pki)?,
            config.agent_pki.bootstrap_materials(&config.identity.instance_id,crate::device_pki::providers(&config.device_pki)?.as_ref(), clock.unix_seconds()?)?,
        )?;
        let access_audit=Arc::new(agent_audit.on_runtime(identity.runtime.clone(),identity.tenant,&rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5)).control()).await?);
        let agent_enrollment = agent_pki
            .as_ref()
            .map(|pki| {
                crate::test_support::agent::application_service(
                    access_audit.clone(),                    pki,
                    &store,
                    agent_audit.clone(),
                    execution.service.clone(),
                )
            })
            .transpose()?;
        let wns=if push {
            // 预置受控 WNS 资格用于协议测试，不作为真实 Microsoft 资格证据。
            use sqlx::Connection;
            let mut owner=sqlx::PgConnection::connect_with(&std::env::var("MDM_OWNER_URL")?.parse::<sqlx::postgres::PgConnectOptions>()?.ssl_mode(sqlx::postgres::PgSslMode::VerifyFull).ssl_root_cert(std::env::var("PG_CA_FILE")?)).await?;
            let mut tx=owner.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
            let material_key=config.native_protector()?;
            let existing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND revision=1)").bind(case_tenant()).fetch_one(&mut *tx).await?;
            if !existing {
                rss_mdm_windows_channel::wns_materials::prepare(&mut tx,case_tenant(),Uuid::new_v4(),"controlled-protocol-fixture",&rss_mdm_windows_channel::wns_materials::Request{expected_revision:0,package_family_name:"fixture.pfn".into(),sid:"fixture-sid".to_owned().into(),client_secret:"fixture-secret".to_owned().into()},&material_key).await?;
                rss_mdm_windows_channel::wns_materials::qualify(&mut tx,case_tenant(),1,now()).await?;
            }
            let value=rss_mdm_windows_channel::wns_materials::load(&mut tx,case_tenant(),1,&material_key,crate::test_support::runtime::monotonic(),true).await?;
            tx.commit().await?;owner.close().await?;Some(value)
        }else{None};
        let mut windows = Windows::load(
            config
                .native_protocols
                .windows
                .expect("Windows test configuration"),
            now(),
            crate::device_pki::providers(&config.device_pki)?,
            wns,
        )?;
        if ca.is_some() {
            // The production host accepts production lifetimes only. Renewal-window
            // participants select a short-lived certificate profile at this existing CA seam.
            let channel = Arc::get_mut(&mut windows.channel).ok_or_else(|| anyhow::anyhow!("unshared renewal fixture channel"))?;
            channel.ca = rss_mdm_device_trust::windows::WindowsDeviceTrust::from_trust(channel.ca.trust.clone())?
                .with_lifetime(rss_mdm_certificate::windows::Lifetime::Development { seconds: 6*86400 })?;
        }
        if let Some((mut binding, verifier, jit)) = entra {
            let view = provider(&identity, &secret, &binding.token, jit).await?;
            binding.provider_id = Uuid::parse_str(&view.id.to_string())?;
            let provider =
                rss_identity_core::federation::ProviderId::parse(&binding.provider_id.to_string())?;
            let authority = rss_identity_postgres::EntraAuthority::new(
                identity.authority.clone(),
                verifier,
                identity.tenant,
                provider,
                binding.token.clone(),
            )?;
            Arc::get_mut(&mut windows.channel).unwrap().entra = Some(Arc::new(
                rss_mdm_windows_channel::entra::Entra::new(authority, identity.tenant, binding)?,
            ));
        }
        let windows = Arc::new(windows);
        let mut trusts = vec![windows.channel.ca.trust.clone()];
        if let Some(a) = &agent_pki {
            trusts.push(a.issuer.trust().trust.clone());
            if let Some(bootstrap) = &a.bootstrap {
                trusts.push(bootstrap.trust.clone());
            }
        }
        let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
            store.archive_pool(),
            command_audit.clone(),
            trusts,
            crate::device_pki::providers(&config.device_pki)?,
        ));
        crate::test_support::pki::seed_trust(&store.archive_pool(), pki.bindings()).await?;
        let associations = Arc::new(rss_mdm_device_service::Associations::new(
            store
                .audit_store_fixture(&crate::config::AuditConfig::Plain)
                .await?,
            rss_request_context::TenantId::parse(case_tenant())?,
            &[7; 32],
        )?);
        let binding = rss_transactional_messaging::fence::ExecutionBinding::new(
            rss_transactional_messaging::fence::StorageIdentity::new(config.flow.storage.target, config.flow.storage.lineage)?,
            vec![(identity.tenant, rss_transactional_messaging::fence::Epoch::new(config.flow.storage.epoch)?)],
        )?;
        let webhooks = crate::webhooks::Backend::open(
            config.webhooks, execution.runtime.clone(), identity.tenant,
            agent_audit.clone(), clock.clone(), execution.protection.clone(), binding,
        ).await?;
        execution.webhooks.set(webhooks.clone()).map_err(|_| anyhow::anyhow!("webhook fixture already assembled"))?;
        resources.resource(crate::webhooks::Resource(webhooks.clone()));
        // This handler fixture owns its real transport outside production assembly.
        if let Some(agent) = &agent_pki {
            execution.channels.set(crate::channel_status::ChannelName::Agent,
                crate::channel_status::ChannelState::Ready, None)?;
            execution.channels.mounted(crate::channel_status::ChannelName::Agent)?;
            execution.channels.installation(agent.clone(), pki.clone())?;
        }
        let app = Arc::new(Assembly {
            access_audit: Some(access_audit),
            platform_configuration: None,
            audit_projection_health: Default::default(),
            channels: execution.channels.clone(),
            telemetry: None,
            runtime_observation: crate::setup::host::Observation::new(&config.runtime_binding, identity.tenant.to_string(), identity.instance.to_string()),
            apple_material_roots: Arc::new(Vec::new()),
            webhooks,
            associations,
            pki,
            agent_enrollment,
            agent_pki,
            certificate_archive: crate::certificate_archive::assemble(
                &store,
                command_audit.clone(),
                clock.clone(),
            ),
            timeline,
            content_writer: execution.content.clone(),
            queries: execution.queries.clone(),
            inputs: execution.inputs.clone(),
            protection: execution.protection.clone(),
            execution_runtime: execution.runtime.clone(),
            audit_store: agent_audit.clone(),
            apple: None,
            execution: execution.service.clone(),
            flow: management,
            identity: Arc::new(identity),
            credentials: Arc::new(credentials),
            clock,
            identity_management,
            inventory: runtime.clone(),
            devices,
            access: store.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
            windows: Some(windows),
        });
        let ingress_clock = IngressClock::new();
        let crate::native::Routers {
            mut browser,
            mut listeners,
            ..
        } = crate::api::from_state(
            app.clone(),
            "mdm.example.test".into(),
            ingress_clock.clone(),
        );
        if let Some(i) = listeners
            .iter()
            .position(|(kind, _)| *kind == crate::native::ChannelKind::Agent)
        {
            browser = crate::test_support::gateway::browser_agent(browser, listeners.remove(i).1.router, "mdm.example.test");
        }
        let root_cert = reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root_cert.clone())
            .timeout(Duration::from_secs(12))
            .build()?;
        Ok(Self {
            resources: Default::default(),
            root,
            app,
            notifications: crate::worker_wake::Listener::new(
                crate::device::test_support::options("mdm_access")?,
                rss_request_context::TenantId::parse(case_tenant())?,
            ),
            browser,
            store,
            runtime,
            ingress_clock,
            root_cert,
            client,
            secret,
            reference,
            listeners,
            enroll: Some(enroll),
            manage: Some(manage),
            additional_manage,
            running: None,
        })

        })).await?;
        fixture.resources = resources;
        Ok(fixture)
    }
    pub(crate) async fn listen(&mut self) -> anyhow::Result<()> {
        let (_, management) = self.listeners.remove(1);
        let (_, mut enrollment) = self.listeners.remove(0);
        enrollment.router = enrollment.router.route(
            "/accepted-peer",
            axum::routing::get(
                |axum::Extension(source): axum::Extension<
                    rss_identity_http_axum::ClientAddress,
                >| async move { source.0.to_string() },
            ),
        );

        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let notifications = self.notifications.clone();
        let signals = notifications.signals.clone();
        let mut startup = owner.startup()?;
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            notifications.clone(),
        ));
        let mut launch = startup.commit();
        launch.stage_task_with_token(notifications.registration().critical());
        if let Some(listener) = self.additional_manage.take() {
            let (kind, router) = self
                .listeners
                .pop()
                .expect("additional management listener");
            launch.stage_task_with_token(
                crate::test_support::gateway::registration(
                    listener,
                    router,
                    self.app.audit_store.clone(),
                    case_tenant().into(),
                    kind,
                )
                .await?
                .critical(),
            );
        }
        for (listener, router, kind) in [
            (
                self.enroll.take().unwrap(),
                enrollment,
                crate::native::ChannelKind::WindowsEnrollment,
            ),
            (
                self.manage.take().unwrap(),
                management,
                crate::native::ChannelKind::WindowsManagement,
            ),
        ] {
            launch.stage_task_with_token(
                crate::test_support::gateway::registration(
                    listener,
                    router,
                    self.app.audit_store.clone(),
                    case_tenant().into(),
                    kind,
                )
                .await?
                .critical(),
            );
        }
        if crate::test_support::case::owns_worker() {
            launch.stage_deferred_task_with_token(
                self.runtime
                    .clone()
                    .registration(signals.handle(crate::worker_wake::Work::Inventory))
                    .critical(),
            );
        }
        launch.finish();
        self.running = Some(owner);
        Ok(())
    }
    /// Drop listener/runtime ownership and reconstruct all product services against committed state.
    pub(crate) async fn restart(self) -> anyhow::Result<Self> {
        let windows = self.app.windows()?;
        let addresses = (
            std::net::SocketAddr::from((
                [127, 0, 0, 1],
                url::Url::parse(&windows.config.enrollment.origin)?
                    .port_or_known_default()
                    .unwrap(),
            )),
            std::net::SocketAddr::from((
                [127, 0, 0, 1],
                url::Url::parse(&windows.config.management.origin)?
                    .port_or_known_default()
                    .unwrap(),
            )),
        );
        let credential =
            rss_identity_core::session::SessionSecret::parse(self.secret.expose().into())?;
        self.close().await?;
        let mut next = Self::bind(
            None,
            rss_device_command_postgres::CommandClock::Postgres,
            Some(addresses),
            Some(credential),
            None,
            false,
            false,
            None,
            false,
        )
        .await?;
        next.listen().await?;
        Ok(next)
    }
    pub(crate) async fn close(mut self) -> anyhow::Result<()> {
        let resources = std::mem::take(&mut self.resources);
        resources
            .finish(async {
                if let Some(owner) = self.running.take() {
                    ensure!(owner.shutdown().join().await?.is_clean());
                }
                Ok(())
            })
            .await
    }
    pub(crate) async fn peer(&self) -> anyhow::Result<Peer> {
        self.peer_profile(rss_mdm_registration_service::enrollment::WindowsProfile::Device)
            .await
    }
    pub(crate) async fn peer_for(&self, device: &str) -> anyhow::Result<Peer> {
        self.peer_with_authority(
            rss_mdm_registration_service::enrollment::WindowsProfile::Device,
            false,
            PeerPreparation::CurrentCredential,
            device,
        )
        .await
    }
    pub(crate) async fn self_peer(&self) -> anyhow::Result<Peer> {
        self.peer_with_authority(
            rss_mdm_registration_service::enrollment::WindowsProfile::Full,
            true,
            PeerPreparation::EnrollmentProtocol,
            crate::test_support::case::name("tls-device"),
        )
        .await
    }
    pub(crate) async fn peer_profile(
        &self,
        profile: rss_mdm_registration_service::enrollment::WindowsProfile,
    ) -> anyhow::Result<Peer> {
        self.peer_with_authority(
            profile,
            false,
            PeerPreparation::CurrentCredential,
            crate::test_support::case::name("tls-device"),
        )
        .await
    }
    pub(crate) async fn enrolled_peer(&self) -> anyhow::Result<Peer> {
        self.peer_with_authority(
            rss_mdm_registration_service::enrollment::WindowsProfile::Device,
            false,
            PeerPreparation::EnrollmentProtocol,
            crate::test_support::case::name("tls-device"),
        )
        .await
    }
    async fn enrollment_receipt(
        &self,
        profile: rss_mdm_registration_service::enrollment::WindowsProfile,
        self_service: bool,
        plain: &str,
    ) -> anyhow::Result<(AuthorizedPrincipal, Password, crate::enrollment::Receipt)> {
        let proof = admin(
            case_tenant(),
            if self_service { "other-a" } else { "admin-a" },
        )
        .await?;
        let password = Password::new(plain.to_owned())?;
        let receipt = if self_service {
            crate::test_support::identity::set_grants(case_tenant(), proof.principal_id(), vec![])
                .await?;
            let secret = crate::test_support::identity::credential(&self.app.identity, "other")?;
            let mut browser = crate::test_support::http::Browser {
                cookies: std::collections::BTreeMap::from([(
                    "__Host-identity-session".into(),
                    secret.expose().into(),
                )]),
                csrf: Some(secret.csrf()),
                operation: Some(Uuid::new_v4()),
                ..Default::default()
            };
            let (status,value)=browser.call(&self.browser,axum::http::Method::POST,"/api/v1/self-enrollments",Some(serde_json::json!({"source":"mdm.windows","password":plain,"windowsProfile":profile}))).await?;
            ensure!(status == StatusCode::OK, "self enrollment {status} {value}");
            serde_json::from_value::<crate::enrollment::Receipt>({
                let mut value = value;
                value.as_object_mut().unwrap().remove("deviceId");
                value
            })?
        } else {
            crate::enrollment::test_support::create_windows(
                &self.store,
                &proof,
                crate::test_support::case::name("tls-device"),
                &password,
                self.reference,
                Uuid::new_v4(),
                profile,
            )
            .await?
        };
        Ok((proof, password, receipt))
    }
    fn issue_request(
        &self,
        profile: rss_mdm_registration_service::enrollment::WindowsProfile,
        enrollment: Uuid,
        plain: &str,
        path: &str,
    ) -> anyhow::Result<soap::Message> {
        let mut issue = soap::decode(
            include_bytes!("../../../windows-mdm/tests/fixtures/issue-request.xml"),
            Operation::Issue,
            &CodecLimits::default(),
        )?;
        issue.header.to = Some(path.to_owned());
        let token = issue
            .header
            .security
            .as_mut()
            .unwrap()
            .username
            .as_mut()
            .unwrap();
        token.username = Secret(
            self.app
                .windows()?
                .channel
                .enrollment_username(enrollment)?,
        );
        token.password = Secret(plain.to_owned());
        let Body::Issue(body) = &mut issue.body else {
            panic!()
        };
        body.request =
            soap::CertificateRequest::Pkcs10(Secret(std::fs::read(self.root.join("device.csr"))?));
        for (key, value) in &mut body.additional_context.0 {
            if key == "EnrollmentType" {
                *value = profile.as_str().to_owned();
            }
            if key == "DeviceID" {
                *value = crate::test_support::case::name("tls-device").into();
            }
        }
        Ok(issue)
    }
    fn initial_message(
        url: &str,
        registration: Uuid,
        device: &str,
        secrets: &rss_mdm_windows_channel::test_support::Secrets,
    ) -> anyhow::Result<syncml::Message> {
        let mut message = syncml::decode(
            include_bytes!("../../../windows-mdm/tests/fixtures/initialization.xml"),
            &CodecLimits::default(),
        )?;
        message.header.target = url.to_owned();
        message.header.source = device.into();
        message.header.credential = Some(syncml::Credential {
            meta: syncml::Meta {
                format: Some("b64".into()),
                media_type: Some("syncml:auth-basic".into()),
                ..Default::default()
            },
            data: Secret(STANDARD.encode(format!(
                "{}:{}",
                registration,
                secrets.client_password.as_str()
            ))),
        });
        for command in &mut message.commands {
            if let Command::DevInfo { items, .. } = command {
                for item in items {
                    if item.source.as_deref() == Some("./DevInfo/DevId") {
                        item.data = Some(Secret(device.into()));
                    }
                }
            }
        }
        Ok(message)
    }
    async fn peer_with_authority(
        &self,
        profile: rss_mdm_registration_service::enrollment::WindowsProfile,
        self_service: bool,
        preparation: PeerPreparation,
        device: &str,
    ) -> anyhow::Result<Peer> {
        self.peer_request(profile, self_service, preparation, device, None)
            .await
    }
    pub(crate) async fn peer_from_agent_handoff(
        &self,
        id: Uuid,
        password: String,
    ) -> anyhow::Result<Peer> {
        self.peer_request(
            rss_mdm_registration_service::enrollment::WindowsProfile::Full,
            false,
            PeerPreparation::EnrollmentProtocol,
            crate::test_support::case::name("tls-device"),
            Some((id, password)),
        )
        .await
    }
    #[allow(
        clippy::cognitive_complexity,
        reason = "one controlled peer preserves real enrollment, current-credential setup and Agent-handoff protocol paths without duplicating identity construction"
    )]
    async fn peer_request(
        &self,
        profile: rss_mdm_registration_service::enrollment::WindowsProfile,
        self_service: bool,
        preparation: PeerPreparation,
        device: &str,
        handoff: Option<(Uuid, String)>,
    ) -> anyhow::Result<Peer> {
        use x509_cert::der::{EncodePem, pem::LineEnding};
        let root = &self.root;
        let app = &self.app;
        let store = &self.store;
        let client = &self.client;
        let root_cert = &self.root_cert;
        let plain = handoff
            .as_ref()
            .map(|v| v.1.clone())
            .unwrap_or_else(crate::enrollment::random);
        let (proof, receipt, seeded) = if matches!(preparation, PeerPreparation::CurrentCredential)
        {
            let proof = admin(case_tenant(), "admin-a").await?;
            let request = Uuid::new_v4();
            let intent = issuance::fixture::intent(
                &app.windows()?.channel,
                case_tenant(),
                request,
                &std::fs::read(root.join("device.csr"))?,
                enrollment_type(profile),
                now(),
            )?;
            let profile = certificate::IssuanceProfile::decode(&intent.profile)?;
            let cert = crate::test_support::pki::leaf(
                &PathBuf::from(std::env::var("MDM_WINDOWS_PKI_FIXTURES")?),
                &intent.csr,
                &intent.registration.to_string(),
                &[],
                profile.start,
                profile.end,
            )?
            .remove(0);
            let mut tx = store.archive_pool().begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(case_tenant())
                .execute(&mut *tx)
                .await?;
            let (receipt, provisioning) = issuance::fixture::current_in(
                &mut tx,
                &app.windows()?.channel,
                &proof,
                issuance::fixture::Seed {
                    request,
                    device,
                    intent: &intent,
                    certificate: &cert,
                    now: now(),
                },
            )
            .await?;
            tx.commit().await?;
            (proof, receipt, Some((intent, cert, provisioning)))
        } else if let Some((id, _)) = &handoff {
            let receipt = crate::enrollment::Receipt {
                operation_id: Uuid::new_v4(),
                enrollment_id: *id,
                status: "pending".into(),
                expires_at: now() + 300,
                registration: None,
                source: rss_mdm_inventory::ReportSource::MdmWindows,
            };
            (admin(case_tenant(), "admin-a").await?, receipt, None)
        } else {
            let (proof, _, receipt) = self
                .enrollment_receipt(profile, self_service, &plain)
                .await?;
            (proof, receipt, None)
        };
        let path = format!(
            "{}/EnrollmentServer/Enrollment.svc",
            app.windows()?.config.enrollment.origin
        );
        let mut issue = self.issue_request(profile, receipt.enrollment_id, &plain, &path)?;
        if self_service && let Body::Issue(body) = &mut issue.body {
            // Descriptive context cannot select the authoritative tenant.
            body.additional_context
                .0
                .push(("TenantID".into(), Uuid::nil().to_string()));
        }
        let mut wire = soap::encode(&issue, &CodecLimits::default())?;
        if self_service {
            wire = String::from_utf8(wire)?.replace(
                "</t:RequestSecurityToken>",
                "<v:Hint xmlns:v=\"urn:example:vendor\">ignored</v:Hint></t:RequestSecurityToken>",
            ).into_bytes();
        }
        let (intent, cert, provisioning) = if let Some(seeded) = seeded {
            seeded
        } else {
            let response = client
                .post(&path)
                .header("content-type", "application/soap+xml")
                .body(wire.clone())
                .send()
                .await?;
            ensure!(
                response.status() == StatusCode::OK,
                "WSTEP failed: {:?}",
                response.status()
            );
            let decoded =
                soap::decode_response(&issue, &response.bytes().await?, &CodecLimits::default())?;
            let Body::IssueResponse(result) = decoded.body else {
                anyhow::bail!("missing issuance response")
            };
            ensure!(String::from_utf8_lossy(&result.provisioning.0).contains("AAUTHLEVEL"));
            let (intent, cert) = if handoff.is_some() {
                let mut tx = store.archive_pool().begin().await?;
                crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
                let observed =
                    issuance::fixture::observed(&mut tx, case_tenant(), receipt.enrollment_id)
                        .await?;
                tx.rollback().await?;
                observed
            } else {
                let auth = crate::enrollment::store::enrollment_authorization(
                    &store.registration(),
                    case_tenant(),
                    receipt.enrollment_id,
                    &Password::new(plain.clone())?,
                )
                .await?;
                let csr = std::fs::read(root.join("device.csr"))?;
                let intent = rss_mdm_windows_channel::issuance::issuance_intent(
                    &store.windows_store(),
                    &app.windows()?.channel,
                    &auth,
                    &proof,
                    (&csr, enrollment_type(profile)),
                    now(),
                )
                .await?;
                let cert = sign_certificate(&app.windows()?.channel.ca, &intent).await?;
                (intent, cert)
            };
            (intent, cert, result.provisioning.0)
        };

        let cert_pem = x509_cert::Certificate::from_der(&cert)?.to_pem(LineEnding::LF)?;
        let identity = reqwest::Identity::from_pem(
            &[
                cert_pem.as_bytes(),
                &std::fs::read(root.join("device.key"))?,
            ]
            .concat(),
        )?;
        let mutual = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root_cert.clone())
            .identity(identity)
            .timeout(Duration::from_secs(12))
            .build()?;
        let url = app
            .windows()?
            .channel
            .management_url(rss_mdm_registration_service::Purpose::Primary);
        let secrets = app.windows()?.channel.open_secrets_fixture(
            case_tenant(),
            receipt.enrollment_id,
            &intent.sealed,
        )?;
        let message = Self::initial_message(&url, intent.registration, device, &secrets)?;
        let next_nonce = [7u8; 16];
        let followup = syncml::Message {
            header: syncml::Header {
                message_id: 2,
                credential: None,
                ..message.header.clone()
            },
            commands: vec![Command::Status(syncml::Status {
                credential: None,
                id: 1,
                message_ref: 1,
                command_ref: 0,
                command: CommandName::SyncHdr,
                target_refs: vec![],
                source_refs: vec![],
                code: 212,
                items: vec![],
                challenge: Some(syncml::Challenge {
                    media_type: "syncml:auth-md5".into(),
                    nonce: Some(Secret(STANDARD.encode(next_nonce))),
                }),
            })],
            final_message: true,
        };
        Ok(Peer {
            profile,
            proof,
            receipt,
            intent,
            secrets,
            issue,
            path,
            wire,
            provisioning,
            certificate: cert,
            mutual,
            url,
            message,
            ack: followup,
        })
    }
}
enum PeerPreparation {
    CurrentCredential,
    EnrollmentProtocol,
}
pub(crate) struct Peer {
    profile: rss_mdm_registration_service::enrollment::WindowsProfile,
    pub(super) proof: AuthorizedPrincipal,
    pub(super) receipt: crate::enrollment::Receipt,
    pub(crate) intent: issuance::Intent,
    pub(super) secrets: rss_mdm_windows_channel::test_support::Secrets,
    pub(super) issue: soap::Message,
    pub(super) path: String,
    pub(super) wire: Vec<u8>,
    pub(super) provisioning: Vec<u8>,
    pub(crate) certificate: Vec<u8>,
    pub(crate) mutual: reqwest::Client,
    pub(crate) url: String,
    pub(crate) message: syncml::Message,
    pub(crate) ack: syncml::Message,
}

impl Host {
    pub(crate) async fn replace(&self, peer: &Peer) -> anyhow::Result<()> {
        let plain = crate::enrollment::random();
        let password = Password::new(plain.clone())?;
        let next = crate::enrollment::test_support::create_windows(
            &self.store,
            &peer.proof,
            crate::test_support::case::name("tls-device"),
            &password,
            self.reference,
            Uuid::new_v4(),
            peer.profile,
        )
        .await?;
        let mut issue = peer.issue.clone();
        issue.header.message_id = Some(format!("urn:uuid:{}", Uuid::new_v4()));
        let token = issue
            .header
            .security
            .as_mut()
            .unwrap()
            .username
            .as_mut()
            .unwrap();
        token.username = Secret(
            self.app
                .windows()?
                .channel
                .enrollment_username(next.enrollment_id)?,
        );
        token.password = Secret(plain);
        let issued = self
            .client
            .post(&peer.path)
            .header("content-type", "application/soap+xml")
            .body(soap::encode(&issue, &CodecLimits::default())?)
            .send()
            .await?;
        ensure!(
            issued.status() == StatusCode::OK,
            "replacement registration: {}",
            issued.status()
        );
        Ok(())
    }
}

async fn management(
    config: &crate::config::Config,
    access: &Database,
    inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    resources: &mut crate::test_support::runtime::Resources,
) -> anyhow::Result<(
    Arc<crate::flow::Flow>,
    Arc<rss_mdm_timeline_service::Timeline>,
)> {
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let flow = config
        .flow
        .open(
            inventory,
            access
                .audit_store_fixture(&crate::config::AuditConfig::Plain)
                .await?,
            tenant,
            Arc::new(crate::clock::SystemClock),
            None,
            |resource| resources.resource(resource),
        )
        .await?;
    let timeline = access.timeline(
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?,
        tenant,
        &flow.cursor_key,
    )?;
    timeline.initialize().await?;
    Ok((flow, timeline))
}

pub(crate) fn fixture_providers() -> anyhow::Result<Arc<rss_mdm_pki_service::providers::Providers>>
{
    Ok(crate::device_pki::providers(&serde_json::from_slice::<
        Vec<crate::device_pki::Provider>,
    >(&std::fs::read(
        root()?.join("device-pki.json"),
    )?)?)?)
}
/// Positive issuance always crosses the real pinned CA transport and persistent attempt store.
pub(crate) async fn sign_certificate(
    ca: &rss_mdm_device_trust::windows::WindowsDeviceTrust,
    intent: &issuance::Intent,
) -> anyhow::Result<Vec<u8>> {
    let access = Database::connect(options("mdm_access")?).await?;
    let audit = access
        .audit_store_fixture(&crate::config::AuditConfig::Plain)
        .await?;
    let providers = fixture_providers()?;
    let registry = rss_mdm_pki_service::registry::Registry::new(
        access.archive_pool(),
        audit.clone(),
        vec![ca.trust.clone()],
        providers.clone(),
    );
    registry
        .admit(rss_request_context::TenantId::parse(case_tenant())?, now())
        .await?;
    let profile = certificate::IssuanceProfile::decode(&intent.profile)?;
    let csr = certificate::Csr::verify(&intent.csr)?;
    let issuer = profile
        .issuer
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut tx = access.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2)",
    )
    .bind(case_tenant())
    .bind(intent.credential)
    .fetch_one(&mut *tx)
    .await?;
    if !exists {
        rss_mdm_pki_service::signing::authorize_in(
            &mut tx,
            Uuid::parse_str(case_tenant())?,
            "windows",
            &issuer,
            providers.get(rss_mdm_agent_wire::pki::Purpose::Windows, &issuer)?,
            rss_mdm_pki_service::Sign {
                attempt: intent.credential,
                csr_pem: &csr.pem()?,
                csr_digest: &csr.digest(),
                subject: &intent.registration.to_string(),
                sans: &[],
                start: profile.start,
                end: profile.end,
                deadline: profile.start + 60,
            },
        )
        .await?;
    }
    tx.commit().await?;
    let chain = rss_mdm_pki_service::signing::SigningStore::new(audit)
        .issue(
            Uuid::parse_str(case_tenant())?,
            ("windows", &issuer),
            providers.get(rss_mdm_agent_wire::pki::Purpose::Windows, &issuer)?,
            rss_mdm_pki_service::Sign {
                attempt: intent.credential,
                csr_pem: &csr.pem()?,
                csr_digest: &csr.digest(),
                subject: &intent.registration.to_string(),
                sans: &[],
                start: profile.start,
                end: profile.end,
                deadline: profile.start + 60,
            },
            now(),
            |chain| {
                let result = ca.validate_issued(
                    &profile,
                    &csr,
                    &chain
                        .iter()
                        .map(|b| b.as_slice().into())
                        .collect::<Vec<_>>(),
                    now(),
                );
                if let Err(error) = &result {
                    eprintln!("Windows fixture CA candidate rejected: {error:?}");
                }
                result.is_ok()
            },
        )
        .await?;
    access.close().await;
    Ok(chain[0].clone())
}

fn federation(
    identity: &crate::identity::Identity,
) -> anyhow::Result<rss_identity_postgres::Federation> {
    Ok(rss_identity_postgres::Federation::new(
        rss_identity_core::groups::GroupFactsMaxAge::new(60)?,
        identity.authority.clone(),
        Arc::new(rss_identity_oidc::HttpOidc::new(Vec::new(), Vec::new())?),
        StateSigner::new([11; 32], "native-fixture")?,
        rss_identity_postgres::FederationConfig {
            callback: "https://mdm.example.test/api/v1/identity/oidc/callback".into(),
            credential_keys: Arc::new(rss_identity_postgres::CredentialKeys::new(
                "fixture".into(),
                vec![("fixture".into(), [22; 32])],
            )?),
            targets: BTreeMap::from([("app".into(), "https://mdm.example.test".into())]),
        },
    )?)
}
async fn provider(
    identity: &crate::identity::Identity,
    secret: &rss_identity_core::session::SessionSecret,
    profile: &EntraTokenProfile,
    jit: bool,
) -> anyhow::Result<ProviderView> {
    let actor = identity
        .authority
        .authenticate_session(
            identity.tenant,
            rss_identity_core::session::SessionSecret::parse(secret.expose().into())?,
            crate::identity::deadline(),
        )
        .await?;
    let f = federation(identity)?;
    let settings: ProviderSettings = ProviderSettingsInput {
        issuer: profile.issuer(),
        client_id: profile.app_id.to_string(),
        redirect_uri: "https://mdm.example.test/api/v1/identity/oidc/callback".into(),
        scopes: vec!["openid".into(), "profile".into()],
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Entra {
                tenant: profile.tenant,
            },
            profile: rss_identity_core::profile::ProfileSettings::default(),
            groups: None,
            department_snapshot: None,
        },
        jit,
    }
    .try_into()?;
    let view = f
        .create_provider(
            actor,
            settings,
            ProviderCredentials::new("fixture-client-secret".into(), None)?,
            crate::identity::deadline(),
        )
        .await?;
    let actor = identity
        .authority
        .authenticate_session(
            identity.tenant,
            rss_identity_core::session::SessionSecret::parse(secret.expose().into())?,
            crate::identity::deadline(),
        )
        .await?;
    Ok(f.enable_provider(
        actor,
        view.id,
        view.version,
        true,
        crate::identity::deadline(),
    )
    .await?)
}

fn enrollment_type(
    profile: rss_mdm_registration_service::enrollment::WindowsProfile,
) -> rss_mdm_windows_mdm::provisioning::EnrollmentType {
    match profile {
        rss_mdm_registration_service::enrollment::WindowsProfile::Full => {
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full
        }
        rss_mdm_registration_service::enrollment::WindowsProfile::Device => {
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Device
        }
    }
}
