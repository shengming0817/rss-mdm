use super::*;
use crate::api::Assembly;
use crate::enrollment::test_support::audit;
use crate::{
    Database,
    assets::collection::CollectionService,
    device::test_support::{admin, options},
    enrollment::{Authorization, Password},
};
use crate::{authorization::context::AuthorizedPrincipal, clock::Clock};
use anyhow::ensure;
use axum::Router;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::syncml::{self, Command, CommandName};
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;
use x509_cert::der::Decode;
pub(crate) fn case_tenant() -> &'static str {
    crate::test_support::case::tenant()
}
pub(super) fn root() -> anyhow::Result<PathBuf> {
    Ok(std::env::var("MDM_WINDOWS_FIXTURES")?.into())
}
pub(crate) fn now() -> i64 {
    crate::clock::SystemClock.unix_seconds().unwrap()
}
pub(super) fn windows() -> anyhow::Result<Windows> {
    let config = serde_json::from_slice(&std::fs::read(root()?.join("windows.json"))?)?;
    Ok(Windows::load(config, now(), None)?)
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
    pub(crate) root: PathBuf,
    pub(crate) app: Arc<Assembly>,
    pub(crate) command_audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) notifications: crate::worker_wake::Listener,
    pub(crate) browser: Router,
    pub(crate) store: Arc<Database>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) ingress_clock: Arc<IngressClock>,
    pub(crate) root_cert: reqwest::Certificate,
    pub(crate) client: reqwest::Client,
    pub(super) secret: rss_identity_core::session::SessionSecret,
    pub(super) reference: Uuid,
    listeners: Vec<(crate::native::NativeListenerKind, crate::native::TlsRouter)>,
    enroll: Option<tokio::net::TcpListener>,
    manage: Option<tokio::net::TcpListener>,
    additional_manage: Option<tokio::net::TcpListener>,
    running: Option<rss_runtime::ShutdownStack>,
}
impl Host {
    /// Prepare in-process product routes; listeners and workers start only in listen().
    pub(crate) async fn open() -> anyhow::Result<Self> {
        Self::with_agent(None, rss_device_command_postgres::CommandClock::Postgres).await
    }
    pub(crate) async fn with_agent(
        agent: Option<serde_json::Value>,
        command_clock: rss_device_command_postgres::CommandClock,
    ) -> anyhow::Result<Self> {
        Self::bind(agent, command_clock, None, None, None, false, false).await
    }
    pub(super) async fn renewal_window() -> anyhow::Result<Self> {
        Self::bind(
            None,
            rss_device_command_postgres::CommandClock::Postgres,
            None,
            None,
            Some("renewal-ca.pem"),
            false,
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
        )
        .await
    }
    pub(crate) async fn with_management_addresses() -> anyhow::Result<Self> {
        Self::bind(
            None,
            rss_device_command_postgres::CommandClock::Postgres,
            None,
            None,
            None,
            false,
            true,
        )
        .await
    }
    #[allow(
        clippy::cognitive_complexity,
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
    ) -> anyhow::Result<Self> {
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
        if let Some(ca) = ca {
            value["native_protocols"]["windows"]["ca_certificate_file"] =
                serde_json::json!(root.join(ca));
        }
        value["native_protocols"]["windows"]["enrollment"]["origin"] =
            serde_json::json!(format!("https://localhost:{}", enroll.local_addr()?.port()));
        value["native_protocols"]["windows"]["enrollment"]["listen"] =
            serde_json::json!(enroll.local_addr()?.to_string());
        value["native_protocols"]["windows"]["management"]["origin"] =
            serde_json::json!(format!("https://localhost:{}", manage.local_addr()?.port()));
        value["native_protocols"]["windows"]["management"]["listen"] =
            serde_json::json!(manage.local_addr()?.to_string());
        value["identity"] = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
            std::env::var("MDM_TEST_CONFIG")?,
        )?)?["identity"]
            .clone();
        value["identity"]["tenant_id"] = serde_json::json!(case_tenant());
        let db: sqlx::postgres::PgConnectOptions = std::env::var("DATABASE_URL")?.parse()?;
        let management_password = root.join("management-password");
        std::fs::write(&management_password, "runtime-fixture")?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&management_password, std::fs::Permissions::from_mode(0o600))?;
        value["flow"]["storage"]["database"] = serde_json::json!({"host":"localhost","port":db.get_port(),"name":db.get_database().unwrap(),"user":"mdm_flow_runtime","password_file":management_password,"ca_file":root.join("ca.crt")});
        value["execution"]["database"] = value["flow"]["storage"]["database"].clone();
        value["execution"]["database"]["user"] = "mdm_command_runtime".into();
        let original: serde_json::Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        value["content"] = original["content"].clone();
        value["native_protection_key_file"] = original["native_protection_key_file"].clone();
        if let Some(agent) = agent {
            value["agent_installation"] = agent;
        }
        if push {
            let secret = root.join(format!("wns-{}-secret", Uuid::new_v4()));
            std::fs::write(&secret, "fixture-secret")?;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600))?;
            value["native_protocols"]["windows"]["push"] = serde_json::json!({"package_family_name":"fixture.pfn","sid":"fixture-sid","client_secret_file":secret});
        }
        if let Some(listener) = &additional_manage {
            let mut endpoint = value["native_protocols"]["windows"]["management"].clone();
            endpoint["listen"] = serde_json::json!(listener.local_addr()?.to_string());
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
                case_tenant(),
                crate::test_support::identity::INSTANCE,
                config.identity_management.clone(),
            )?,
        );
        let identity =
            crate::identity::Identity::connect(&config, identity_management.clone(), |_| {})
                .await?;
        let secret = admin_session(&identity, credential).await?;
        let credentials = crate::enrollment::credentials::Credentials::new(monotonic(), 100);
        let reference = credentials.insert(rss_identity_core::session::SessionSecret::parse(
            secret.expose().into(),
        )?)?;
        let store = Arc::new(Database::connect(options("mdm_access")?).await?);
        let devices = Arc::new(crate::device::DeviceService::new(
            store.registration(),
            case_tenant().into(),
            store
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        ));
        let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
            options("mdm_runtime")?,
            store.inventory(),
            rss_request_context::TenantId::parse(case_tenant())?,
            monotonic(),
            store
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await?;
        let (management, timeline) = management(&config, &store).await?;
        let command_audit = store
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?;
        let content = {
            let _guard = crate::test_support::software::content_setup_guard().await?;
            crate::execution_assembly::open_content(&config, config.native_protector()?)?
        };
        let execution = crate::execution_assembly::open(
            &config,
            config.native_protector()?,
            command_audit.clone(),
            content,
            std::collections::BTreeMap::new(),
            command_clock,
        )
        .await
        .map_err(|e| anyhow::anyhow!("command startup: {e:?}"))?;
        let app = Arc::new(Assembly {
            timeline,
            content_writer: execution.content.clone(),
            queries: execution.queries.clone(),
            inputs: execution.inputs.clone(),
            protection: execution.protection.clone(),
            execution_runtime: execution.runtime.clone(),
            audit_store: store
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
            apple: None,
            execution: execution.service.clone(),
            flow: management,
            identity: Arc::new(identity),
            credentials: Arc::new(credentials),
            clock,
            identity_management,
            collection: Arc::new(CollectionService::new(
                devices.clone(),
                store.inventory(),
                runtime.clone(),
            )),
            inventory: runtime.clone(),
            devices,
            access: store.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
            windows: Some(Arc::new(Windows::load(
                config
                    .native_protocols
                    .windows
                    .expect("Windows test configuration"),
                now(),
                config
                    .agent_installation
                    .identity(rss_mdm_policy::Platform::Windows)
                    .cloned(),
            )?)),
        });
        let ingress_clock = IngressClock::new();
        let crate::native::Routers {
            browser, listeners, ..
        } = crate::api::from_state(
            app.clone(),
            "mdm.example.test".into(),
            ingress_clock.clone(),
        );
        let root_cert = reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root_cert.clone())
            .timeout(Duration::from_secs(12))
            .build()?;
        Ok(Self {
            root,
            app,
            command_audit,
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
    }
    pub(crate) async fn listen(&mut self) -> anyhow::Result<()> {
        let (_, management) = self.listeners.remove(1);
        let (_, mut enrollment) = self.listeners.remove(0);
        enrollment.router = enrollment.router.route(
            "/accepted-peer",
            axum::routing::get(
                |axum::Extension(info): axum::Extension<
                    rss_axum::AcceptedConnectionInfo<(
                        Option<rss_mdm_certificate::HandshakePeer>,
                        admission::RequestGate,
                    )>,
                >| async move { info.socket_peer().ip().to_string() },
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
                tls::registration(
                    listener,
                    router,
                    self.app.audit_store.clone(),
                    case_tenant().into(),
                    kind,
                )
                .critical(),
            );
        }
        for (listener, router, kind) in [
            (
                self.enroll.take().unwrap(),
                enrollment,
                crate::native::NativeListenerKind::WindowsEnrollment,
            ),
            (
                self.manage.take().unwrap(),
                management,
                crate::native::NativeListenerKind::WindowsManagement,
            ),
        ] {
            launch.stage_task_with_token(
                tls::registration(
                    listener,
                    router,
                    self.app.audit_store.clone(),
                    case_tenant().into(),
                    kind,
                )
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
            windows.config.enrollment.listen,
            windows.config.management.listen,
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
        )
        .await?;
        next.listen().await?;
        Ok(next)
    }
    pub(crate) async fn close(mut self) -> anyhow::Result<()> {
        if let Some(owner) = self.running.take() {
            ensure!(owner.shutdown().join().await?.is_clean());
        }
        self.runtime.close_fixture().await?;
        self.store.close().await;
        Ok(())
    }
    pub(crate) async fn peer(&self) -> anyhow::Result<Peer> {
        self.peer_profile(rss_mdm_registration_service::enrollment::WindowsProfile::Device)
            .await
    }
    pub(crate) async fn peer_profile(
        &self,
        profile: rss_mdm_registration_service::enrollment::WindowsProfile,
    ) -> anyhow::Result<Peer> {
        use x509_cert::der::{EncodePem, pem::LineEnding};
        let root = &self.root;
        let app = &self.app;
        let store = &self.store;
        let reference = self.reference;
        let client = &self.client;
        let root_cert = &self.root_cert;
        let proof = admin(case_tenant(), "admin-a").await?;
        let plain = crate::enrollment::random();
        let password = Password::new(plain.clone())?;
        let receipt = crate::enrollment::test_support::create_windows(
            store,
            &proof,
            crate::test_support::case::name("tls-device"),
            &password,
            reference,
            Uuid::new_v4(),
            profile,
        )
        .await?;
        let path = format!(
            "{}/EnrollmentServer/Enrollment.svc",
            app.windows()?.config.enrollment.origin
        );
        let mut issue = soap::decode(
            include_bytes!("../../../windows-mdm/tests/fixtures/issue-request.xml"),
            Operation::Issue,
            &CodecLimits::default(),
        )?;
        issue.header.to = Some(path.clone());
        let token = issue
            .header
            .security
            .as_mut()
            .unwrap()
            .username
            .as_mut()
            .unwrap();
        token.username = Secret(receipt.enrollment_id.to_string());
        token.password = Secret(plain);
        let Body::Issue(body) = &mut issue.body else {
            panic!()
        };
        body.request =
            soap::CertificateRequest::Pkcs10(Secret(std::fs::read(root.join("device.csr"))?));
        for (key, value) in &mut body.additional_context.0 {
            if key == "EnrollmentType" {
                *value = profile.as_str().to_owned();
            }
            if key == "DeviceID" {
                *value = crate::test_support::case::name("tls-device").into();
            }
        }
        let wire = soap::encode(&issue, &CodecLimits::default())?;
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
        let first = response.bytes().await?;
        let decoded = soap::decode_response(&issue, &first, &CodecLimits::default())?;
        let Body::IssueResponse(result) = decoded.body else {
            panic!()
        };
        ensure!(String::from_utf8_lossy(&result.provisioning.0).contains("AAUTHLEVEL"));
        let auth = crate::enrollment::store::enrollment_authorization(
            &store.registration(),
            case_tenant(),
            receipt.enrollment_id,
            &password,
        )
        .await?;
        let csr = std::fs::read(root.join("device.csr"))?;
        let intent = rss_mdm_windows_channel::issuance::issuance_intent(
            &store.windows_store(),
            &app.windows()?.channel,
            &auth,
            &proof,
            (
                &csr,
                match profile {
                    rss_mdm_registration_service::enrollment::WindowsProfile::Full => {
                        rss_mdm_windows_mdm::provisioning::EnrollmentType::Full
                    }
                    rss_mdm_registration_service::enrollment::WindowsProfile::Device => {
                        rss_mdm_windows_mdm::provisioning::EnrollmentType::Device
                    }
                },
            ),
            now(),
        )
        .await?;
        let cert = app
            .windows()?
            .channel
            .ca
            .sign(&app.windows()?.channel.ca.restore_intent(
                &intent.tbs,
                &certificate::Csr::verify(&intent.csr)?,
                intent.registration,
            )?)?;
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
        let mut message = syncml::decode(
            include_bytes!("../../../windows-mdm/tests/fixtures/initialization.xml"),
            &CodecLimits::default(),
        )?;
        message.header.target = url.clone();
        message.header.source = crate::test_support::case::name("tls-device").into();
        let secrets =
            app.windows()?
                .channel
                .open_secrets_fixture(case_tenant(), auth.id, &intent.sealed)?;
        message.header.credential = Some(syncml::Credential {
            meta: syncml::Meta {
                format: Some("b64".into()),
                media_type: Some("syncml:auth-basic".into()),
                ..Default::default()
            },
            data: Secret(STANDARD.encode(format!(
                "{}:{}",
                intent.registration,
                secrets.client_password.as_str()
            ))),
        });
        for command in &mut message.commands {
            if let Command::DevInfo { items, .. } = command {
                for item in items {
                    if item.source.as_deref() == Some("./DevInfo/DevId") {
                        item.data =
                            Some(Secret(crate::test_support::case::name("tls-device").into()));
                    }
                }
            }
        }
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
            provisioning: result.provisioning.0,
            mutual,
            url,
            message,
            ack: followup,
        })
    }
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
        token.username = Secret(next.enrollment_id.to_string());
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
) -> anyhow::Result<(
    Arc<crate::flow::Flow>,
    Arc<rss_mdm_timeline_service::Timeline>,
)> {
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let flow = config
        .flow
        .open(
            access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
            tenant,
            Arc::new(crate::clock::SystemClock),
            None,
            |_| {},
        )
        .await?;
    let timeline = access.timeline(
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
        tenant,
        &flow.cursor_key,
    )?;
    timeline.initialize().await?;
    Ok((flow, timeline))
}

/// Exercise HTTP absolute-form over the actual old mutual TLS socket, bypassing client URL normalization.
pub(crate) async fn absolute_form_post(
    host: &Host,
    peer: &Peer,
    target: &str,
    message: &syncml::Message,
) -> anyhow::Result<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::{
        self,
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject,
        },
    };
    let ca = &host.app.windows()?.channel.ca;
    let cert = ca.sign(&ca.restore_intent(
        &peer.intent.tbs,
        &certificate::Csr::verify(&peer.intent.csr)?,
        peer.intent.registration,
    )?)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(&std::fs::read(
        host.root.join("ca.crt"),
    )?)?)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_client_auth_cert(
        vec![cert.into()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
            host.root.join("device.pk8"),
        )?)),
    )?;
    let endpoint = reqwest::Url::parse(&peer.url)?;
    let socket =
        tokio::net::TcpStream::connect(("127.0.0.1", endpoint.port_or_known_default().unwrap()))
            .await?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut tls = connector
        .connect(ServerName::try_from("localhost")?, socket)
        .await?;
    let body = syncml::encode(message, &CodecLimits::default())?;
    let wire = format!(
        "POST {target} HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: application/vnd.syncml.dm+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.port_or_known_default().unwrap(),
        body.len()
    );
    tls.write_all(wire.as_bytes()).await?;
    tls.write_all(&body).await?;
    tls.flush().await?;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        tls.take(1024 * 1024).read_to_end(&mut response),
    )
    .await??;
    Ok(std::str::from_utf8(&response)?
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status"))?
        .parse()?)
}
