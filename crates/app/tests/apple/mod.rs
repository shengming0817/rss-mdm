#![allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and persistence assertions"
)]
//! Real Apple mTLS participant and fixed external SCEP provider; no principal or status stubs.
mod commands;
mod ddm;
mod lifecycle;
mod onboarding;
mod oracle;
mod policy;
mod scep;
#[path = "support/scep.rs"]
mod scep_client;
mod status;
mod users;
use super::*;
use crate::{
    api::Assembly,
    clock::Clock,
    native::{self, tls},
    test_support::Browser,
};
use anyhow::{Result, ensure};
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
    app: Arc<Assembly>,
    browser: Browser,
    router: Router,
    owner: rss_runtime::ShutdownStack,
    signals: Arc<crate::worker_wake::Signals>,
    root: PathBuf,
    lose_notify: Arc<std::sync::atomic::AtomicBool>,
}
impl Fixture {
    async fn start() -> Result<Self> {
        Self::with_agent(None).await
    }
    async fn with_agent(agent: Option<serde_json::Value>) -> Result<Self> {
        Self::with_endpoint(agent, None, false).await
    }
    async fn with_endpoint(
        agent: Option<serde_json::Value>,
        address: Option<std::net::SocketAddr>,
        preserve_authorization: bool,
    ) -> Result<Self> {
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let manage =
            tokio::net::TcpListener::bind(address.unwrap_or("127.0.0.1:0".parse()?)).await?;
        let webhook = tokio::net::TcpListener::bind(
            std::env::var("MDM_APPLE_WEBHOOK_LISTEN").unwrap_or_else(|_| "127.0.0.1:0".into()),
        )
        .await?;
        if std::env::var_os("MDM_STEP_CA_URL").is_some() {
            publish_webhooks(&root, webhook.local_addr()?).await?;
        }
        let mut config = crate::test_support::identity::config(case_tenant())?;
        config.native_protocols.windows = None;
        if let Some(agent) = agent {
            config.agent_installation = serde_json::from_value(agent)?;
        }
        let mut apple: config::Config =
            serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
        apple.management.listen = manage.local_addr()?;
        apple.management.origin = format!("https://localhost:{}", manage.local_addr()?.port());
        config.native_protocols.apple = Some(apple);
        let compiled = config.compile()?;
        let config = &compiled.config;
        let clock = Arc::new(crate::clock::SystemClock);
        let monotonic: Arc<dyn rss_observation::Clock> = fixture_clock();
        let access = Arc::new(crate::Database::connect(config.access_database.options()?).await?);
        let devices = Arc::new(
            crate::device::DeviceService::new(
                access.registration(),
                case_tenant().into(),
                access
                    .audit_store(&crate::config::AuditConfig::Plain)
                    .await?,
            )
            .with_retirement_test_budget(Duration::from_secs(30)),
        );
        // This fixture checks 65+ exact terminal facts, not a six-second throughput promise.

        let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
            config.runtime_database.options()?,
            access.inventory(),
            rss_request_context::TenantId::parse(case_tenant())?,
            monotonic.clone(),
            access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await?;
        let management = config
            .flow
            .open(
                access
                    .audit_store(&crate::config::AuditConfig::Plain)
                    .await?,
                rss_request_context::TenantId::parse(case_tenant())?,
                clock.clone(),
                None,
                |_| {},
            )
            .await?;
        let content = {
            let _guard = crate::test_support::software::content_setup_guard().await?;
            crate::execution_assembly::open_content(config, config.native_protector()?).await?
        };
        let execution = crate::execution_assembly::open(
            config,
            config.native_protector()?,
            access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
            content,
            std::collections::BTreeMap::new(),
            rss_device_command_postgres::CommandClock::Postgres,
        )
        .await?;
        let identity = crate::identity::Identity::connect(
            config,
            compiled.identity_management.clone(),
            |_| {},
        )
        .await?;
        let config = compiled.config;
        let timeline = access.timeline(
            access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
            identity.tenant,
            &management.cursor_key,
        )?;
        timeline.initialize().await?;
        let agent_audit = access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?;
        let agent_pki = config.agent_pki.load(
            agent_audit.clone(),
            clock.clone(),
            crate::device_pki::providers(&config.device_pki)?,
        )?;
        let agent_enrollment = agent_pki
            .as_ref()
            .map(|pki| {
                crate::test_support::agent::application_service(
                    pki,
                    &access,
                    agent_audit.clone(),
                    execution.service.clone(),
                )
            })
            .transpose()?;
        let apple = Arc::new(Apple::load(
            execution.protection.clone(),
            config.native_protocols.apple.unwrap(),
            crate::clock::SystemClock.unix_seconds()?,
            crate::device_pki::providers(&config.device_pki)?,
            config
                .agent_installation
                .identity(rss_mdm_policy::Platform::Macos)
                .cloned(),
        )?);
        let mut trusts = vec![apple.channel.device_trust().clone()];
        if let Some(a) = &agent_pki {
            trusts.push(a.issuer.trust().trust.clone());
        }
        let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
            access.archive_pool(),
            agent_audit.clone(),
            trusts,
            crate::device_pki::providers(&config.device_pki)?,
        ));
        pki.admit(
            rss_request_context::TenantId::parse(case_tenant())?,
            crate::clock::SystemClock.unix_seconds()?,
        )
        .await?;
        let app = Arc::new(Assembly {
            pki,
            agent_enrollment,
            agent_pki,
            certificate_archive: crate::certificate_archive::assemble(
                &access,
                access
                    .audit_store(&crate::config::AuditConfig::Plain)
                    .await?,
                Arc::new(crate::clock::SystemClock),
            ),
            timeline,
            content_writer: execution.content.clone(),
            queries: execution.queries.clone(),
            inputs: execution.inputs.clone(),
            protection: execution.protection.clone(),
            execution_runtime: execution.runtime.clone(),
            audit_store: access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
            execution: execution.service.clone(),
            flow: management,
            identity: Arc::new(identity),
            credentials: Arc::new(crate::enrollment::credentials::Credentials::new(
                monotonic.clone(),
                100,
            )),
            clock,
            identity_management: compiled.identity_management,
            collection: Arc::new(crate::assets::collection::CollectionService::new(
                devices.clone(),
                access.inventory(),
                runtime.clone(),
            )),
            inventory: runtime.clone(),
            devices,
            windows: None,
            apple: Some(apple),
            access: access.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
        });
        let native::Routers {
            browser: mut router,
            mut listeners,
            ..
        } = crate::api::from_state(app.clone(), "mdm.example.test".into(), monotonic.clone());
        if let Some(i) = listeners
            .iter()
            .position(|(kind, _)| *kind == crate::native::NativeListenerKind::Agent)
        {
            router = router.merge(listeners.remove(i).1.router);
        }
        ensure!(listeners.len() == 1, "Apple-only assembly loaded Windows");
        let (_, native) = listeners.pop().unwrap();
        let hook_origin = format!("https://mdm.example.test:{}", webhook.local_addr()?.port());
        let endpoint = native::TlsEndpoint {
            listen: webhook.local_addr()?,
            origin: hook_origin.clone(),
            certificate_file: root.join("server.crt"),
            private_key_file: root.join("apple-tls.pk8"),
        };
        let hooks = crate::api::from_state(
            app.clone(),
            hook_origin.trim_start_matches("https://").into(),
            monotonic.clone(),
        )
        .browser;
        let lose_notify = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failure = lose_notify.clone();
        let hooks = hooks.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let failure = failure.clone();
                async move {
                    use axum::response::IntoResponse;
                    if request.uri().path() == "/api/v1/apple/scep/notify"
                        && failure.load(std::sync::atomic::Ordering::SeqCst)
                    {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    next.run(request).await
                }
            },
        ));
        let hooks = native::TlsRouter {
            admission: native::admission::Admission::new(
                monotonic,
                app.requests.clone(),
                "apple-webhook-fixture",
            ),
            listen: endpoint.listen,
            tls: tls::configuration(&endpoint, None)?,
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
                tls::registration(
                    manage,
                    native,
                    access
                        .audit_store(&crate::config::AuditConfig::Plain)
                        .await?,
                    case_tenant().into(),
                    crate::native::NativeListenerKind::AppleManagement,
                )
                .critical(),
            );
            launch.stage_task_with_token(
                tls::registration(
                    webhook,
                    hooks,
                    access
                        .audit_store(&crate::config::AuditConfig::Plain)
                        .await?,
                    case_tenant().into(),
                    crate::native::NativeListenerKind::AppleWebhookFixture,
                )
                .critical(),
            );
            launch.stage_deferred_task_with_token(
                execution
                    .service
                    .registration(signals.execution())
                    .critical(),
            );
            launch.stage_deferred_task_with_token(
                runtime
                    .registration(signals.handle(crate::worker_wake::Work::Inventory))
                    .critical(),
            );
            launch.finish();
        }
        if !preserve_authorization {
            crate::test_support::identity::set_grants(
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
        let browser = crate::test_support::authority::Authority::open()
            .await?
            .browser("admin")?;
        Ok(Self {
            app,
            browser,
            router,
            owner,
            signals,
            root,
            lose_notify,
        })
    }
    async fn profile_query_due(&self, operation: Uuid) -> Result<()> {
        use sqlx::Connection;
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        // Advance only the durable read retry clock; request, receipt and eligibility remain intact.
        let count = sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp() WHERE tenant_id=$1::uuid AND operation=$2 AND phase='observe'")
            .bind(case_tenant()).bind(operation).execute(&mut pg).await?.rows_affected();
        ensure!(count > 0);
        pg.close().await?;
        Ok(())
    }
    async fn grant_native_actions(&self, extra: &[&str]) -> Result<()> {
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
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            crate::test_support::identity::device_grants(Some(case_device()), &operations)?,
        )
        .await
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
            crate::test_support::identity::set_grants(case_tenant(), proof.principal_id(), vec![])
                .await?;
            let secret = crate::test_support::identity::credential(&self.app.identity, "other")?;
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
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/enrollments/{enrollment}/profile"))
            .header("host", "mdm.example.test")
            .header("content-type", "application/json")
            .body(Body::from(json!({"password":password}).to_string()))?;
        let response = self.router.clone().oneshot(request).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "Apple profile download {}",
            response.status()
        );
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
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
        ("/trust_file", "AgentPki"),
        ("/profile_certificate_file", "AppleProfileSigner"),
        ("/apns_certificate_file", "AppleApns"),
        ("/challenge_webhook/secret_file", "AppleChallengeWebhook"),
        ("/notify_webhook/secret_file", "AppleNotifyWebhook"),
    ] {
        let mut input = original.clone();
        *input.pointer_mut(pointer).unwrap() = json!("private-material-path-must-not-be-logged");
        let config = serde_json::from_value(input)?;
        match Apple::load(
            crate::test_support::identity::config(case_tenant())?.native_protector()?,
            config,
            crate::clock::SystemClock.unix_seconds()?,
            fixture_providers(root)?,
            None,
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
        crate::clock::SystemClock.unix_seconds()?,
        fixture_providers(root)?,
        None,
    )?;
    ensure!(
        apple
            .channel
            .health(crate::clock::SystemClock.unix_seconds()?)
            .is_ready()
    );
    for expires in [
        apple.channel.trust_fixture().expires(),
        apple.channel.signer_expiration_fixture(),
        apple.channel.push_fixture().expires,
    ] {
        ensure!(!apple.channel.health(expires as i64).is_ready());
    }
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
    async fn close(self) -> Result<()> {
        let report = self.owner.shutdown().join().await?;
        if !report.is_clean() {
            let diagnostics = self
                .app
                .inventory
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
        ensure!(report.is_clean(), "Apple fixture shutdown: {report:?}");
        Ok(())
    }
    async fn scep_leaf(&mut self) -> Result<(scep_client::Device, Vec<u8>)> {
        let (enrollment, attempt, password) = self.enrollment().await?;
        let device = scep_client::Device::new(enrollment, attempt, &password)?;
        let request = device.request(
            &self.root.join("apple-issuer.pem"),
            &Uuid::new_v4().to_string(),
            self.app.clock.unix_seconds()?,
        )?;
        let der = device
            .enroll(
                &self.client()?,
                &self.app.apple()?.channel.scep_fixture()?.0,
                &request,
            )
            .await?;
        Ok((device, der))
    }
    async fn local_leaf(&mut self) -> Result<(scep_client::Device, Vec<u8>)> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let (enrollment, attempt, password) = self.enrollment().await?;
        let device = scep_client::Device::new(enrollment, attempt, &password)?;
        let apple = self.app.apple()?;
        let timestamp = time::OffsetDateTime::from_unix_timestamp(self.app.clock.unix_seconds()?)?
            .format(&time::format_description::well_known::Rfc3339)?;
        let body = serde_json::to_vec(
            &json!({"timestamp":timestamp,"provisionerName":apple.channel.scep_fixture()?.1,
            "x509CertificateRequest":{"raw":STANDARD.encode(&device.csr)},"scepChallenge":password,"scepTransactionID":Uuid::new_v4().to_string()}),
        )?;
        let signature = apple
            .channel
            .challenge_signature_fixture(&body)
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/apple/scep/challenge")
                    .header("host", "mdm.example.test")
                    .header("content-type", "application/json")
                    .header("x-smallstep-webhook-id", &apple.config.challenge_webhook.id)
                    .header("x-smallstep-signature", signature)
                    .body(Body::from(body))?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "fixture challenge: {}",
            response.status()
        );
        let extensions = device.root.path().join("leaf.ext");
        std::fs::write(
            &extensions,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n",
        )?;
        let leaf = device.root.path().join("leaf.der");
        let serial = Uuid::new_v4().as_u128().to_string();
        scep_client::openssl(&[
            "x509".as_ref(),
            "-req".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-in".as_ref(),
            device.root.path().join("device.csr").as_os_str(),
            "-CA".as_ref(),
            self.root.join("apple-issuer.pem").as_os_str(),
            "-CAkey".as_ref(),
            self.root.join("apple-issuer.key").as_os_str(),
            "-set_serial".as_ref(),
            serial.as_ref(),
            "-days".as_ref(),
            "1".as_ref(),
            "-sha256".as_ref(),
            "-extfile".as_ref(),
            extensions.as_os_str(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-out".as_ref(),
            leaf.as_os_str(),
        ])?;
        let der = std::fs::read(leaf)?;
        Ok((device, der))
    }
    async fn authenticate_peer(
        &self,
        device: &scep_client::Device,
        der: &[u8],
    ) -> Result<lifecycle::Peer> {
        let apple = self.app.apple()?;
        let peer = lifecycle::Peer {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(40))
                .identity(device.identity(der)?)
                .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                    self.root.join("ca.crt"),
                )?)?)
                .build()?,
            oracle: oracle::Oracle::new(der)?,
            origin: apple.config.management.origin.clone(),
            topic: apple.config.apns_topic.clone(),
        };
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
    async fn ready_local_peer(&mut self) -> Result<(lifecycle::Peer, scep_client::Device)> {
        let (device, der) = self.local_leaf().await?;
        let peer = self.authenticate_peer(&device, &der).await?;
        peer.token().await?;
        Ok((peer, device))
    }
    async fn ready_scep_peer(&mut self) -> Result<(lifecycle::Peer, scep_client::Device)> {
        let (device, der) = self.scep_leaf().await?;
        let peer = self.authenticate_peer(&device, &der).await?;
        peer.token().await?;
        Ok((peer, device))
    }
    async fn pending_collections(&mut self, count: usize) -> Result<()> {
        for _ in 0..count {
            let reply = self
                .browser
                .call(
                    &self.router,
                    Method::POST,
                    &format!(
                        "/api/v1/devices/{DEVICE}/collection-runs",
                        DEVICE = case_device()
                    ),
                    Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
                )
                .await?;
            ensure!(
                reply.0 == StatusCode::ACCEPTED,
                "fixture collection intake: {reply:?}"
            );
        }
        Ok(())
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
async fn publish_webhooks(root: &std::path::Path, address: std::net::SocketAddr) -> Result<()> {
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
            .env(
                "STEPPATH",
                std::path::PathBuf::from(std::env::var("MDM_APPLE_PKI_FIXTURES")?).join("step"),
            )
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
