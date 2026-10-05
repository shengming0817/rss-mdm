//! Product T2: controlled Apple HTTPS, real database, signed CMS, SCEP and mTLS.
use super::*;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sqlx::Connection;

#[derive(Default)]
struct Remote {
    organization: Uuid,
    profile: Uuid,
    configuration: Value,
    session: usize,
    pages: usize,
    assigned: bool,
    lose_profile: bool,
}
async fn session(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let authorized = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.starts_with("OAuth realm=\"ADM\"")
                && v.contains("oauth_signature=")
                && v.contains("oauth_signature_method=\"HMAC-SHA1\"")
        });
    if !authorized {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    let mut s = state.lock().await;
    s.session += 1;
    (
        StatusCode::OK,
        Json(json!({"auth_session_token":format!("session-{}",s.session)})),
    )
}
async fn account(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let s = state.lock().await;
    if headers
        .get("X-ADM-Auth-Session")
        .and_then(|v| v.to_str().ok())
        != Some(format!("session-{}", s.session).as_str())
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    (
        StatusCode::OK,
        Json(json!({"server_uuid":s.organization,"org_id":"T2-organization"})),
    )
}
async fn sync(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let mut s = state.lock().await;
    s.pages += 1;
    let serial = crate::test_support::case::name("ade-serial");
    if body.get("cursor").is_none() {
        Json(
            json!({"devices":[{"serial_number":serial,"device_assigned_date":"2026-10-01T00:00:00Z","profile_uuid":null}],"cursor":"page-1","more_to_follow":true}),
        )
    } else {
        Json(json!({"devices":[],"cursor":"page-2","more_to_follow":false}))
    }
}
async fn define_profile(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let mut s = state.lock().await;
    s.configuration = body;
    if s.lose_profile {
        s.lose_profile = false;
        return (StatusCode::OK, Json(json!({})));
    }
    (StatusCode::OK, Json(json!({"profile_uuid":s.profile})))
}
async fn get_profile(State(state): State<Arc<tokio::sync::Mutex<Remote>>>) -> Json<Value> {
    Json(state.lock().await.configuration.clone())
}
async fn assign(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.lock().await.assigned = true;
    Json(
        json!({"devices":body["devices"].as_array().unwrap().iter().map(|d|(d.as_str().unwrap().to_owned(),json!("SUCCESS"))).collect::<serde_json::Map<_,_>>()}),
    )
}
async fn clear(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.lock().await.assigned = false;
    Json(
        json!({"devices":body["devices"].as_array().unwrap().iter().map(|d|(d.as_str().unwrap().to_owned(),json!("SUCCESS"))).collect::<serde_json::Map<_,_>>()}),
    )
}
async fn details(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let s = state.lock().await;
    Json(
        json!({"devices":body["devices"].as_array().unwrap().iter().map(|d|(d.as_str().unwrap().to_owned(),json!({"profile_uuid":if s.assigned{Some(s.profile)}else{None}}))).collect::<serde_json::Map<_,_>>()}),
    )
}
struct Control {
    f: Fixture,
    state: Arc<tokio::sync::Mutex<Remote>>,
    owner: rss_runtime::ShutdownStack,
    organization: Uuid,
    profile: Uuid,
}
impl Control {
    async fn start() -> Result<Self> {
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let organization = Uuid::new_v4();
        let profile = Uuid::new_v4();
        let state = Arc::new(tokio::sync::Mutex::new(Remote {
            organization,
            profile: Uuid::new_v4(),
            ..Default::default()
        }));
        let router = Router::new()
            .route("/session", get(session))
            .route("/account", get(account))
            .route("/server/devices", post(sync))
            .route("/devices/sync", post(sync))
            .route("/profile", post(define_profile).get(get_profile))
            .route("/profile/devices", put(assign).delete(clear))
            .route("/devices", post(details))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("https://localhost:{}", listener.local_addr()?.port());
        let endpoint = native::TlsEndpoint {
            listen: listener.local_addr()?,
            origin: origin.clone(),
            certificate_file: root.join("server.crt"),
            private_key_file: root.join("apple-tls.pk8"),
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                root.join("ca.crt"),
            )?)?)
            .build()?;
        let der = root.join("ade-manufacturer.der");
        scep_client::openssl(&[
            "x509".as_ref(),
            "-in".as_ref(),
            root.join("apple-root.pem").as_os_str(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-out".as_ref(),
            der.as_os_str(),
        ])?;
        let f = Fixture::with_ade_endpoint(
            None,
            None,
            false,
            Some(rss_mdm_apple_channel::ade::Fixture {
                client,
                origin,
                manufacturer_root: std::fs::read(der)?,
            }),
        )
        .await?;
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let tls = native::TlsRouter {
            admission: native::admission::Admission::new(
                fixture_clock(),
                Arc::new(tokio::sync::Semaphore::new(4)),
                "ade-api-fixture",
            ),
            listen: endpoint.listen,
            tls: tls::configuration(&endpoint, None)?,
            router,
        };
        let startup = owner.startup()?;
        let mut launch = startup.commit();
        launch.stage_task_with_token(
            tls::registration(
                listener,
                tls,
                f.app.audit_store.clone(),
                case_tenant().into(),
                native::NativeListenerKind::AppleWebhookFixture,
            )
            .critical(),
        );
        launch.finish();
        Ok(Self {
            f,
            state,
            owner,
            organization,
            profile,
        })
    }
    fn path(&self) -> String {
        format!("/api/v1/apple/organizations/{}/ade", self.organization)
    }
    async fn command(&mut self, body: Value) -> Result<Uuid> {
        let id = Uuid::new_v4();
        self.f.browser.operation = Some(id);
        let response = self
            .f
            .browser
            .call(
                &self.f.router,
                Method::POST,
                &format!("{}/operations", self.path()),
                Some(body),
            )
            .await?;
        ensure!(response.0 == StatusCode::OK, "ADE command: {response:?}");
        Ok(id)
    }
    async fn cycle(&self) -> Result<()> {
        ensure!(rss_mdm_apple_channel::ade::worker::cycle(&self.f.ade).await?);
        Ok(())
    }
    async fn setup(&mut self) -> Result<()> {
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            serde_json::from_value(json!([
                {"operation":"authorization_read","scope":{"kind":"tenant"}},
                {"operation":"authorization_write","scope":{"kind":"tenant"}}
            ]))?,
        )
        .await?;
        self.f.browser.operation = Some(Uuid::new_v4());
        let input = json!({"expectedRevision":0,"enabled":true,"serverUuid":self.organization,"orgId":"T2-organization","rotateKey":false});
        let created = self
            .f
            .browser
            .call(
                &self.f.router,
                Method::PUT,
                &format!("{}/configuration", self.path()),
                Some(input.clone()),
            )
            .await?;
        ensure!(created.0 == StatusCode::OK, "configuration: {created:?}");
        ensure!(
            self.f
                .browser
                .call(
                    &self.f.router,
                    Method::PUT,
                    &format!("{}/configuration", self.path()),
                    Some(input)
                )
                .await?
                == created,
            "configuration exact replay"
        );
        let certificate = account_enrollment::request(
            &self.f,
            Method::GET,
            &format!("{}/public-key", self.path()),
            vec![],
            &[("cookie", account_enrollment::cookies(&self.f.browser, None))],
        )
        .await?;
        ensure!(certificate.0 == StatusCode::OK);
        let temporary = tempfile::tempdir()?;
        let cert = temporary.path().join("public.pem");
        let plain = temporary.path().join("token.json");
        let envelope = temporary.path().join("token.p7m");
        std::fs::write(&cert, certificate.2)?;
        std::fs::write(
            &plain,
            format!(
                "Content-Type: text/plain\r\n\r\n{}",
                json!({"consumer_key":"fixture-consumer","consumer_secret":"fixture-secret","access_token":"fixture-access","access_secret":"fixture-access-secret","access_token_expiry":"2030-01-01T00:00:00Z"})
            ),
        )?;
        scep_client::openssl(&[
            "smime".as_ref(),
            "-encrypt".as_ref(),
            "-aes256".as_ref(),
            "-binary".as_ref(),
            "-in".as_ref(),
            plain.as_os_str(),
            "-out".as_ref(),
            envelope.as_os_str(),
            cert.as_os_str(),
        ])?;
        self.command(json!({"kind":"token","expectedRevision":1,"p7m":STANDARD.encode(std::fs::read(envelope)?)})).await?;
        self.command(json!({"kind":"sync","full":true})).await?;
        self.cycle().await?;
        let listed = self
            .f
            .browser
            .call(
                &self.f.router,
                Method::GET,
                &format!("{}/devices", self.path()),
                None,
            )
            .await?;
        ensure!(
            listed.1["items"].as_array().unwrap().is_empty(),
            "incomplete full snapshot was published"
        );
        self.cycle().await?;
        self.command(json!({"kind":"profile","id":self.profile,"expectedRevision":0,"configuration":{"name":"T2 ADE","mandatory":true,"removable":false,"skip":["AppleID","Intelligence"]}})).await?;
        self.cycle().await?;
        self.command(json!({"kind":"assign","profile":self.profile,"revision":1,"devices":[crate::test_support::case::name("ade-serial")]})).await?;
        self.cycle().await?;
        Ok(())
    }
    fn machine(&self) -> Result<Vec<u8>> {
        let signer = rss_mdm_certificate::apple::ProfileSigner::from_bytes(
            &std::fs::read(self.f.root.join("apple-profile.pem"))?,
            &std::fs::read(self.f.root.join("apple-profile.pk8"))?,
            self.f.app.clock.unix_seconds()?,
        )?;
        Ok(signer.sign(
            &protocol::xml(protocol::dictionary([
                (
                    "SERIAL",
                    crate::test_support::case::name("ade-serial").into(),
                ),
                (
                    "UDID",
                    crate::test_support::case::name("rss-t2-apple").into(),
                ),
                ("PRODUCT", "Mac14,2".into()),
                ("OS_VERSION", "15.0".into()),
                ("VERSION", "24A335".into()),
            ]))?,
            self.f.app.clock.unix_seconds()?,
        )?)
    }
    async fn enroll(&self, bytes: Vec<u8>) -> Result<(StatusCode, Vec<u8>)> {
        let result = account_enrollment::request(
            &self.f,
            Method::POST,
            &format!(
                "/api/v1/apple/ade/enroll/{}/{}",
                self.organization, self.profile
            ),
            bytes,
            &[],
        )
        .await?;
        Ok((result.0, result.2))
    }
    async fn close(self) -> Result<()> {
        self.f.close().await?;
        ensure!(self.owner.shutdown().join().await?.is_clean());
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.ade: credential, page publication, organization native admission, SCEP and mTLS"]
async fn organization_ade_enrolls_without_a_user_or_personal_quota() -> Result<()> {
    let mut c = Control::start().await?;
    c.setup().await?;
    ensure!(c.enroll(vec![0; 64]).await?.0 != StatusCode::OK);
    let machine = c.machine()?;
    let signed = c.enroll(machine.clone()).await?;
    ensure!(
        signed.0 == StatusCode::OK,
        "ADE profile: {} {}",
        signed.0,
        String::from_utf8_lossy(&signed.1)
    );
    ensure!(
        c.enroll(machine).await?.1 == signed.1,
        "CMS retry changed profile"
    );
    let d = account_enrollment::plist_cms(&signed.1)?;
    ensure!(d["PayloadRemovalDisallowed"].as_boolean() == Some(true));
    let enrollment = Uuid::parse_str(d["PayloadUUID"].as_string().unwrap())?;
    let scep = d["PayloadContent"].as_array().unwrap()[0]
        .as_dictionary()
        .unwrap();
    let attempt = Uuid::parse_str(scep["PayloadUUID"].as_string().unwrap())?;
    let challenge = scep["PayloadContent"].as_dictionary().unwrap()["Challenge"]
        .as_string()
        .unwrap();
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let identity:(bool,String)=sqlx::query_as("SELECT q.self_service,g.actor FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND q.id=$2").bind(case_tenant()).bind(enrollment).fetch_one(&mut pg).await?;
    ensure!(identity == (false, "service:apple-ade".into()));
    let device = scep_client::Device::new(enrollment, attempt, challenge)?;
    let csr = device.request(
        &c.f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        c.f.app.clock.unix_seconds()?,
    )?;
    let der = device
        .enroll(
            &c.f.client()?,
            &c.f.app.apple()?.channel.scep_fixture()?.0,
            &csr,
        )
        .await?;
    let peer = c.f.authenticate_peer(&device, &der).await?;
    peer.token().await?;
    let bound: bool = sqlx::query_scalar(
        "SELECT state='bound' FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(enrollment)
    .fetch_one(&mut pg)
    .await?;
    ensure!(bound);
    pg.close().await?;
    c.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.ade: unknown profile resolution and assignment invalidation"]
async fn unknown_profile_is_resolved_and_unassignment_revokes_pending_admission() -> Result<()> {
    let mut c = Control::start().await?;
    c.setup().await?;
    let machine = c.machine()?;
    let signed = c.enroll(machine.clone()).await?;
    ensure!(signed.0 == StatusCode::OK);
    c.command(json!({"kind":"clear","devices":[crate::test_support::case::name("ade-serial")]}))
        .await?;
    c.cycle().await?;
    ensure!(
        c.enroll(machine).await?.0 != StatusCode::OK,
        "unassigned pending enrollment remained usable"
    );
    c.state.lock().await.lose_profile = true;
    let op=c.command(json!({"kind":"profile","id":c.profile,"expectedRevision":1,"configuration":{"name":"Resolved ADE","mandatory":true,"removable":true,"skip":[]}})).await?;
    c.cycle().await?;
    let status =
        c.f.browser
            .call(
                &c.f.router,
                Method::GET,
                &format!("{}/operations/{op}", c.path()),
                None,
            )
            .await?;
    ensure!(status.1["state"] == "unknown");
    let remote = c.state.lock().await.profile;
    c.command(json!({"kind":"resolve","operation":op,"remoteProfile":remote}))
        .await?;
    c.cycle().await?;
    let status =
        c.f.browser
            .call(
                &c.f.router,
                Method::GET,
                &format!("{}/operations/{op}", c.path()),
                None,
            )
            .await?;
    ensure!(status.1["state"] == "succeeded");
    c.close().await
}
