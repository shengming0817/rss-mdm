#![allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and persistence assertions"
)]
//! Real Apple mTLS participant and fixed external SCEP provider; no principal or status stubs.
mod lifecycle;
mod oracle;
mod policy;
mod scep;
#[path = "support/scep.rs"]
mod scep_client;
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
    root: PathBuf,
    lose_notify: Arc<std::sync::atomic::AtomicBool>,
}
impl Fixture {
    async fn start() -> Result<Self> {
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let manage = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let webhook = tokio::net::TcpListener::bind(format!(
            "127.0.0.1:{}",
            std::env::var("MDM_APPLE_WEBHOOK_PORT").unwrap_or_else(|_| "0".into())
        ))
        .await?;
        let mut config = crate::test_support::identity::config(case_tenant())?;
        config.native_protocols.windows = None;
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
                access.clone(),
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
            access.clone(),
            rss_request_context::TenantId::parse(case_tenant())?,
            monotonic.clone(),
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
                |_| {},
            )
            .await?;
        let execution = crate::flow::execution::open(
            config,
            access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await?;
        let identity = crate::identity::Identity::connect(
            config,
            compiled.identity_management.clone(),
            |_| {},
        )
        .await?;
        let config = compiled.config;
        let app = Arc::new(Assembly {
            content_writer: None,
            audit_store: access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
            execution: execution.clone(),
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
                access.clone(),
                runtime.clone(),
            )),
            readiness: runtime.readiness.clone(),
            devices,
            windows: None,
            apple: Some(Arc::new(Apple::load(
                config.native_protocols.apple.unwrap(),
                crate::clock::SystemClock.unix_seconds()?,
            )?)),
            access: access.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
        });
        let native::Routers {
            browser: router,
            mut listeners,
            ..
        } = crate::api::from_state(app.clone(), "mdm.example.test".into(), monotonic.clone());
        ensure!(listeners.len() == 1, "Apple-only assembly loaded Windows");
        let (_, native) = listeners.pop().unwrap();
        let hook_origin = format!("https://localhost:{}", webhook.local_addr()?.port());
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
                    if request.uri().path() == "/native/apple/scep/notify"
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
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        {
            let mut launch = owner.startup()?.commit();
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
            launch.stage_deferred_task_with_token(execution.registration().critical());
            launch.stage_deferred_task_with_token(runtime.registration().critical());
            launch.finish();
        }
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
                    "firewall_write",
                    "operation_read",
                    "operation_cancel",
                ],
            )?,
        )
        .await?;
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
            root,
            lose_notify,
        })
    }
    async fn enrollment(&mut self) -> Result<(Uuid, Uuid, String)> {
        let password = crate::enrollment::random();
        self.browser.operation = Some(Uuid::new_v4());
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                "/api/v3/enrollments",
                Some(json!({"deviceId":case_device(),"source":"mdm.apple","password":password})),
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK, "Apple enrollment {reply:?}");
        self.browser.operation = None;
        let enrollment = Uuid::parse_str(reply.1["enrollmentId"].as_str().unwrap())?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v3/enrollments/{enrollment}/profile"))
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
        ("/issuer_certificate_file", "AppleScep"),
        ("/profile_certificate_file", "AppleProfileSigner"),
        ("/apns_certificate_file", "AppleApns"),
        ("/challenge_webhook/secret_file", "AppleChallengeWebhook"),
        ("/notify_webhook/secret_file", "AppleNotifyWebhook"),
    ] {
        let mut input = original.clone();
        *input.pointer_mut(pointer).unwrap() = json!("private-material-path-must-not-be-logged");
        let config = serde_json::from_value(input)?;
        match Apple::load(config, crate::clock::SystemClock.unix_seconds()?) {
            Err(crate::Error::Configuration(issue)) => ensure!(
                format!("{issue:?}") == category,
                "wrong startup category for {pointer}"
            ),
            _ => anyhow::bail!("missing startup category for {pointer}"),
        }
    }
    let apple = Apple::load(
        serde_json::from_value(original)?,
        crate::clock::SystemClock.unix_seconds()?,
    )?;
    ensure!(apple.ready(crate::clock::SystemClock.unix_seconds()?));
    for expires in [
        apple.authority.expires(),
        apple.signer.expires(),
        apple.push.expires,
    ] {
        ensure!(!apple.ready(expires as i64));
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
        ensure!(self.owner.shutdown().join().await?.is_clean());
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
                &self.app.apple()?.config.scep_url,
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
            &json!({"timestamp":timestamp,"provisionerName":apple.config.scep_provisioner,
            "x509CertificateRequest":{"raw":STANDARD.encode(&device.csr)},"scepChallenge":password,"scepTransactionID":Uuid::new_v4().to_string()}),
        )?;
        let signature = ring::hmac::sign(&apple.challenge_key, &body)
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
                    .uri("/native/apple/scep/challenge")
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
