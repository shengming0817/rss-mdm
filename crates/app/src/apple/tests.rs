#![allow(
    clippy::cognitive_complexity,
    reason = "sequential real protocol and persistence assertions"
)]
//! Real Apple mTLS participant and fixed external SCEP provider; no principal or status stubs.
mod boundaries;
mod lifecycle;
mod oracle;
#[path = "tests/push_cycle.rs"]
mod push_cycle;
mod scep;
use super::*;
use crate::{
    api::App,
    clock::Clock,
    identity_t2::Browser,
    native::{self, tls},
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
const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "apple-native-mac";
struct Fixture {
    app: Arc<App>,
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
            std::env::var("MDM_APPLE_WEBHOOK_PORT")?
        ))
        .await?;
        let mut config = crate::identity_fixture::config(TENANT)?;
        config.native_protocols.windows = None;
        startup_diagnostics(&root)?;
        let mut apple: config::Config =
            serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
        apple.management.listen = manage.local_addr()?;
        apple.management.origin = format!("https://localhost:{}", manage.local_addr()?.port());
        config.native_protocols.apple = Some(apple);
        let compiled = config.compile()?;
        let config = &compiled.config;
        let clock = Arc::new(crate::clock::SystemClock);
        let monotonic: Arc<dyn rss_observation::Clock> = fixture_clock();
        let access =
            Arc::new(crate::AccessStore::connect(config.access_database.options()?).await?);
        let devices = Arc::new(crate::device::DeviceService::new(
            access.clone(),
            TENANT.into(),
        ));
        let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
            config.runtime_database.options()?,
            access.clone(),
            rss_request_context::TenantId::parse(TENANT)?,
            monotonic.clone(),
        )
        .await?;
        let management = config
            .management
            .open(
                rss_request_context::TenantId::parse(TENANT)?,
                clock.clone(),
                |_| {},
            )
            .await?;
        let commands = crate::commands::Commands::open(config).await?;
        let identity = crate::identity::Identity::connect(
            config,
            compiled.identity_management.clone(),
            |_| {},
        )
        .await?;
        let config = compiled.config;
        let app = Arc::new(App {
            commands: commands.clone(),
            management,
            identity,
            credentials: crate::enrollment_credentials::Credentials::new(monotonic.clone(), 100),
            clock,
            identity_management: compiled.identity_management,
            collection: crate::access::CollectionService::new(
                devices.clone(),
                access.clone(),
                runtime.clone(),
            ),
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
                    access.clone(),
                    TENANT.into(),
                    "apple-management-tls",
                )
                .critical(),
            );
            launch.stage_task_with_token(
                tls::registration(
                    webhook,
                    hooks,
                    access,
                    TENANT.into(),
                    "apple-webhook-fixture",
                )
                .critical(),
            );
            launch.stage_deferred_task_with_token(commands.registration().critical());
            launch.stage_deferred_task_with_token(runtime.registration().critical());
            launch.finish();
        }
        crate::identity_fixture::set_grants(
            TENANT,
            crate::identity_fixture::ADMIN,
            crate::identity_fixture::device_grants(
                Some(DEVICE),
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
        let mut browser = Browser::default();
        let reply = browser
            .call(
                &router,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/login"),
                Some(json!({"login":"admin","password":crate::identity_fixture::PASSWORD})),
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK, "Apple browser login {reply:?}");
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
                Some(json!({"deviceId":DEVICE,"source":"mdm.apple","password":password})),
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
    async fn close(self) -> Result<()> {
        ensure!(self.owner.shutdown().join().await?.is_clean());
        Ok(())
    }
}
#[tokio::test]
#[ignore = "Apple T2: real step-ca SCEP, PostgreSQL and native mTLS"]
async fn native_enrollment_collection_and_profile_lifecycle() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (enrollment, attempt, password) = f.enrollment().await?;
    let device = scep::Device::new(enrollment, attempt, &password)?;
    let apple = f.app.apple()?;
    let request = device.request(
        &f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        f.app.clock.unix_seconds()?,
    )?;
    f.lose_notify
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let der = device
        .enroll(&f.client()?, &apple.config.scep_url, &request)
        .await?;
    f.lose_notify
        .store(false, std::sync::atomic::Ordering::SeqCst);
    boundaries::unbound_leaf_and_replay(&f, &device, &request, attempt).await?;
    let checked = apple.authority.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(
            der.clone(),
        )],
        f.app.clock.unix_seconds()?,
    )?;
    ensure!(checked.enrollment == enrollment && checked.attempt == attempt);
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .identity(device.identity(&der)?)
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            f.root.join("ca.crt"),
        )?)?)
        .build()?;
    let body = protocol::xml(protocol::dictionary([
        ("MessageType", "Authenticate".into()),
        ("UDID", "rss-apple-t2".into()),
        ("Topic", apple.config.apns_topic.clone().into()),
    ]))?;
    let oracle = oracle::Oracle::new(&der)?;
    let response = client
        .put(format!("{}/checkin", apple.config.management.origin))
        .body(body.clone())
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "native Authenticate {}",
        response.status()
    );
    oracle.compare("/checkin", &body, &[]).await?;
    let peer = lifecycle::Peer {
        client,
        oracle,
        origin: apple.config.management.origin.clone(),
        topic: apple.config.apns_topic.clone(),
    };
    f.before_token(&peer).await?;
    peer.token().await?;
    f.push_cycle(&peer).await?;
    f.collection_cycle(&peer).await?;
    f.profile_cycle(&peer).await?;
    let replacement = f.replace(&peer, &device).await?;
    f.native_boundaries(&replacement).await?;
    f.close().await
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
