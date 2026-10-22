//! Product T2: controlled Apple HTTPS, real database, signed CMS, SCEP and mTLS.
use super::*;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sqlx::Connection;

#[derive(Default)]
struct Gate {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[derive(Default)]
struct Remote {
    organization: Uuid,
    profile: Uuid,
    configuration: Value,
    session: usize,
    pages: usize,
    assigned: bool,
    lose_profile: bool,
    lose_assign: bool,
    drop_assign_once: bool,
    drop_clear_once: bool,
    incomplete_details_once: bool,
    throttle_assign_once: bool,
    assignments: Vec<Vec<String>>,
    details_fail_once: bool,
    cursor_fail_once: bool,
    sync_responses: std::collections::VecDeque<Value>,
    reject_session_once: bool,
    block: Option<Arc<Gate>>,
    snapshot_serial: Option<String>,
    additional_serial: Option<String>,
    origin: String,
}
fn verify_oauth(headers: &HeaderMap, origin: &str) -> Result<bool> {
    use std::io::Write;
    let Some(header) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("OAuth realm=\"ADM\","))
    else {
        return Ok(false);
    };
    let encoded = header
        .split(',')
        .map(|p| p.replacen("=\"", "=", 1).trim_end_matches('"').to_owned())
        .collect::<Vec<_>>()
        .join("&");
    let mut fields = url::form_urlencoded::parse(encoded.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let Some(signature) = fields.remove("oauth_signature") else {
        return Ok(false);
    };
    if fields.get("oauth_consumer_key").map(String::as_str) != Some("fixture-consumer")
        || fields.get("oauth_token").map(String::as_str) != Some("fixture-access")
        || fields.get("oauth_signature_method").map(String::as_str) != Some("HMAC-SHA1")
    {
        return Ok(false);
    }
    let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let parameters = fields
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let input = format!(
        "GET&{}&{}",
        encode(&format!("{origin}/session")),
        encode(&parameters)
    );
    let mut child = std::process::Command::new("openssl")
        .args([
            "dgst",
            "-sha1",
            "-hmac",
            "fixture-secret&fixture-access-secret",
            "-binary",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    let signed = child.wait_with_output()?;
    Ok(signed.status.success() && STANDARD.decode(signature)? == signed.stdout)
}
async fn session(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut s = state.lock().await;
    if !verify_oauth(&headers, &s.origin).unwrap_or(false) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
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
) -> axum::response::Response {
    let (serial, profile, additional, gate) = {
        let mut s = state.lock().await;
        s.pages += 1;
        if body.get("cursor").is_some() && s.cursor_fail_once {
            s.cursor_fail_once = false;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error_code":"INVALID_CURSOR"})),
            )
                .into_response();
        }
        if let Some(response) = s.sync_responses.pop_front() {
            return Json(response).into_response();
        }
        (
            s.snapshot_serial
                .clone()
                .unwrap_or_else(|| crate::test_support::case::name("ade-serial").into()),
            if s.assigned { Some(s.profile) } else { None },
            s.additional_serial.clone(),
            if body.get("cursor").is_none() {
                s.block.take()
            } else {
                None
            },
        )
    };
    if let Some(gate) = gate {
        gate.started.notify_one();
        gate.release.notified().await;
    }
    if body.get("cursor").is_none() {
        let mut devices = vec![
            json!({"serial_number":serial,"device_assigned_date":"2026-10-01T00:00:00.123456Z","profile_uuid":profile}),
        ];
        if let Some(serial) = additional {
            devices.push(json!({"serial_number":serial,"device_assigned_date":"2026-10-01T00:00:00.123456Z","profile_uuid":profile}));
        }
        Json(json!({"devices":devices,"cursor":"page-1","more_to_follow":true})).into_response()
    } else {
        Json(json!({"devices":[],"cursor":"page-2","more_to_follow":false})).into_response()
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
) -> axum::response::Response {
    let mut s = state.lock().await;
    let devices = body["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    s.assignments.push(devices.clone());
    if s.drop_assign_once {
        s.drop_assign_once = false;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "request lost before effect",
        )
            .into_response();
    }
    if s.throttle_assign_once {
        s.throttle_assign_once = false;
        return Json(json!({"devices":devices.iter().enumerate().map(|(i,d)|(d.clone(),json!(if i==0{"SUCCESS"}else{"THROTTLED"}))).collect::<serde_json::Map<_,_>>(),"retry_after_seconds":120})).into_response();
    }
    s.assigned = true;
    if s.lose_assign {
        s.lose_assign = false;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "upstream disconnected after commit",
        )
            .into_response();
    }
    Json(json!({"devices":body["devices"].as_array().unwrap().iter().map(|d|(d.as_str().unwrap().to_owned(),json!("SUCCESS"))).collect::<serde_json::Map<_,_>>()})).into_response()
}
async fn clear(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let mut s = state.lock().await;
    if s.drop_clear_once {
        s.drop_clear_once = false;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "request lost before effect",
        )
            .into_response();
    }
    s.assigned = false;
    Json(
        json!({"devices":body["devices"].as_array().unwrap().iter().map(|d|(d.as_str().unwrap().to_owned(),json!("SUCCESS"))).collect::<serde_json::Map<_,_>>()}),
    ).into_response()
}
async fn details(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let mut s = state.lock().await;
    if s.details_fail_once {
        s.details_fail_once = false;
        return (StatusCode::INTERNAL_SERVER_ERROR, "unavailable").into_response();
    }
    if s.incomplete_details_once {
        s.incomplete_details_once = false;
        return Json(json!({"devices":body["devices"].as_array().unwrap().iter().map(|d|(d.as_str().unwrap().to_owned(),json!({}))).collect::<serde_json::Map<_,_>>()})).into_response();
    }
    Json(json!({"devices":body["devices"].as_array().unwrap().iter().map(|d|(d.as_str().unwrap().to_owned(),json!({"profile_uuid":if s.assigned{Some(s.profile)}else{None},"profile_status":if s.assigned{"assigned"}else{"empty"}}))).collect::<serde_json::Map<_,_>>()})).into_response()
}
async fn check_session(
    State(state): State<Arc<tokio::sync::Mutex<Remote>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if request.uri().path() != "/session" {
        let mut s = state.lock().await;
        if s.reject_session_once {
            s.reject_session_once = false;
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if request
            .headers()
            .get("X-Server-Protocol-Version")
            .and_then(|v| v.to_str().ok())
            != Some("10")
            || request
                .headers()
                .get("X-ADM-Auth-Session")
                .and_then(|v| v.to_str().ok())
                != Some(format!("session-{}", s.session).as_str())
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    next.run(request).await
}
/// Four certificates and the historical SHA-1/expired Device CA, matching Apple's
/// positive device-identity policy. Ordinary profile signers share the root but fail it.
fn manufacturer(root: &std::path::Path) -> Result<tempfile::TempDir> {
    let out = tempfile::tempdir()?;
    let ca_ext = out.path().join("ca.ext");
    let leaf_ext = out.path().join("leaf.ext");
    std::fs::write(
        &ca_ext,
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
    )?;
    std::fs::write(
        &leaf_ext,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n",
    )?;
    for (name, cn, parent, parent_key, bits, days, hash) in [
        (
            "manufacturing",
            "Apple iPhone Certification Authority",
            root.join("apple-root.pem"),
            root.join("apple-root.key"),
            "2048",
            "90",
            "-sha256",
        ),
        (
            "device-ca",
            "Apple iPhone Device CA",
            out.path().join("manufacturing.pem"),
            out.path().join("manufacturing.key"),
            "1024",
            "365",
            "-sha1",
        ),
        (
            "machine",
            "RSS ADE device identity",
            out.path().join("device-ca.pem"),
            out.path().join("device-ca.key"),
            "2048",
            "30",
            "-sha256",
        ),
    ] {
        let key = out.path().join(format!("{name}.key"));
        let csr = out.path().join(format!("{name}.csr"));
        let cert = out.path().join(format!("{name}.pem"));
        scep_client::openssl(&[
            "req".as_ref(),
            "-new".as_ref(),
            "-newkey".as_ref(),
            format!("rsa:{bits}").as_ref(),
            "-nodes".as_ref(),
            "-subj".as_ref(),
            format!("/CN={cn}").as_ref(),
            "-keyout".as_ref(),
            key.as_os_str(),
            "-out".as_ref(),
            csr.as_os_str(),
        ])?;
        if name == "device-ca" {
            let config = out.path().join("historical-ca.conf");
            std::fs::write(out.path().join("index"), "")?;
            std::fs::write(out.path().join("serial"), "01\n")?;
            std::fs::write(
                &config,
                format!(
                    "[ca]\ndefault_ca=fixture\n[fixture]\ndatabase={0}/index\nserial={0}/serial\nnew_certs_dir={0}\ncertificate={1}\nprivate_key={2}\ndefault_md=sha1\npolicy=policy\n[policy]\ncommonName=supplied\n",
                    out.path().display(),
                    parent.display(),
                    parent_key.display()
                ),
            )?;
            scep_client::openssl(&[
                "ca".as_ref(),
                "-batch".as_ref(),
                "-notext".as_ref(),
                "-config".as_ref(),
                config.as_os_str(),
                "-in".as_ref(),
                csr.as_os_str(),
                "-out".as_ref(),
                cert.as_os_str(),
                "-startdate".as_ref(),
                "20100101000000Z".as_ref(),
                "-enddate".as_ref(),
                "20140101000000Z".as_ref(),
                "-extfile".as_ref(),
                ca_ext.as_os_str(),
            ])?;
            continue;
        }
        scep_client::openssl(&[
            "x509".as_ref(),
            "-req".as_ref(),
            "-in".as_ref(),
            csr.as_os_str(),
            "-CA".as_ref(),
            parent.as_os_str(),
            "-CAkey".as_ref(),
            parent_key.as_os_str(),
            "-set_serial".as_ref(),
            Uuid::new_v4().as_u128().to_string().as_ref(),
            "-days".as_ref(),
            days.as_ref(),
            hash.as_ref(),
            "-extfile".as_ref(),
            if name == "machine" {
                leaf_ext.as_os_str()
            } else {
                ca_ext.as_os_str()
            },
            "-out".as_ref(),
            cert.as_os_str(),
        ])?;
    }
    scep_client::openssl(&[
        "pkcs8".as_ref(),
        "-topk8".as_ref(),
        "-nocrypt".as_ref(),
        "-in".as_ref(),
        out.path().join("machine.key").as_os_str(),
        "-outform".as_ref(),
        "DER".as_ref(),
        "-out".as_ref(),
        out.path().join("machine.pk8").as_os_str(),
    ])?;
    let mut chain = std::fs::read(out.path().join("machine.pem"))?;
    for name in ["device-ca", "manufacturing"] {
        chain.extend(std::fs::read(out.path().join(format!("{name}.pem")))?);
    }
    std::fs::write(out.path().join("machine-chain.pem"), chain)?;
    Ok(out)
}
struct Control {
    f: Fixture,
    state: Arc<tokio::sync::Mutex<Remote>>,
    owner: rss_runtime::ShutdownStack,
    organization: Uuid,
    profile: Uuid,
    manufacturer: tempfile::TempDir,
}
impl Control {
    async fn start() -> Result<Self> {
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let manufacturer = manufacturer(&root)?;
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
            .route("/profile/devices", post(assign).delete(clear))
            .route("/devices", post(details))
            .with_state(state.clone())
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                check_session,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("https://localhost:{}", listener.local_addr()?.port());
        state.lock().await.origin = origin.clone();
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
            crate::test_support::gateway::registration(
                listener,
                tls,
                f.app.audit_store.clone(),
                case_tenant().into(),
                native::NativeListenerKind::AppleWebhookFixture,
            )
            .await?
            .critical(),
        );
        launch.finish();
        Ok(Self {
            f,
            state,
            owner,
            organization,
            profile,
            manufacturer,
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
    async fn prepared_directory(&mut self) -> Result<()> {
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            serde_json::from_value(json!([
                {"operation":"registration_configuration_read","scope":{"kind":"tenant"}},
                {"operation":"registration_configuration_write","scope":{"kind":"tenant"}}
            ]))?,
        )
        .await?;
        let remote_profile = self.state.lock().await.profile;
        let mut tx = self.f.app.access.archive_pool().begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *tx)
            .await?;
        let configuration = rss_mdm_apple_channel::ade::fixture::seed_in(&mut tx, &self.f.app.protection,
            rss_mdm_apple_channel::ade::fixture::Directory {
                tenant: case_tenant(), organization: self.organization, profile: self.profile, remote_profile,
                serial: crate::test_support::case::name("ade-serial"),
                token: &serde_json::to_vec(&json!({"consumer_key":"fixture-consumer","consumer_secret":"fixture-secret","access_token":"fixture-access","access_secret":"fixture-access-secret","access_token_expiry":"2030-01-01T00:00:00Z"}))?,
                configuration: json!({"name":"T2 ADE","mandatory":true,"removable":false,"skip":["AppleID","Intelligence"]}),
                origin: &self.f.ade.authentication.origin, now: self.f.app.clock.unix_seconds()?,
            }).await?;
        tx.commit().await?;
        let mut state = self.state.lock().await;
        state.assigned = true;
        state.configuration = configuration;
        Ok(())
    }
    async fn setup(&mut self) -> Result<()> {
        crate::test_support::identity::set_grants(
            case_tenant(),
            crate::test_support::case::admin(),
            serde_json::from_value(json!([
                {"operation":"registration_configuration_read","scope":{"kind":"tenant"}},
                {"operation":"registration_configuration_write","scope":{"kind":"tenant"}}
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
            &std::fs::read(self.manufacturer.path().join("machine-chain.pem"))?,
            &std::fs::read(self.manufacturer.path().join("machine.pk8"))?,
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
    fn coordinates(bytes: &[u8]) -> Result<(Uuid, Uuid, String)> {
        let d = account_enrollment::plist_cms(bytes)?;
        let e = Uuid::parse_str(d["PayloadUUID"].as_string().unwrap())?;
        let p = d["PayloadContent"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap();
        Ok((
            e,
            Uuid::parse_str(p["PayloadUUID"].as_string().unwrap())?,
            p["PayloadContent"].as_dictionary().unwrap()["Challenge"]
                .as_string()
                .unwrap()
                .into(),
        ))
    }
    async fn result(&mut self, op: Uuid) -> Result<Value> {
        let r = self
            .f
            .browser
            .call(
                &self.f.router,
                Method::GET,
                &format!("{}/operations/{op}", self.path()),
                None,
            )
            .await?;
        ensure!(r.0 == StatusCode::OK);
        Ok(r.1)
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
    c.f.browser.operation = Some(Uuid::new_v4());
    let quota = c
        .f
        .browser
        .call(
            &c.f.router,
            Method::PUT,
            "/api/v1/registration-quotas/defaults",
            Some(json!({"expectedRevision":0,"limits":{"agent":0,"windows_mdm":0,"macos_mdm":0}})),
        )
        .await?;
    ensure!(quota.0 == StatusCode::OK, "zero personal quota: {quota:?}");
    ensure!(c.enroll(vec![0; 64]).await?.0 != StatusCode::OK);
    let machine = c.machine()?;
    let ordinary = rss_mdm_certificate::apple::ProfileSigner::from_bytes(
        &std::fs::read(c.f.root.join("apple-profile.pem"))?,
        &std::fs::read(c.f.root.join("apple-profile.pk8"))?,
        c.f.app.clock.unix_seconds()?,
    )?;
    let forged = ordinary.sign(
        &protocol::xml(account_enrollment::plist_cms(&machine)?)?,
        c.f.app.clock.unix_seconds()?,
    )?;
    ensure!(
        c.enroll(forged).await?.0 != StatusCode::OK,
        "ordinary same-root signer became a manufacturing identity"
    );
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
    c.prepared_directory().await?;
    let machine = c.machine()?;
    let signed = c.enroll(machine.clone()).await?;
    ensure!(signed.0 == StatusCode::OK);
    let (old_id, old_attempt, old_challenge) = Control::coordinates(&signed.1)?;
    let old_device = scep_client::Device::new(old_id, old_attempt, &old_challenge)?;
    let old_csr = old_device.request(
        &c.f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        c.f.app.clock.unix_seconds()?,
    )?;
    c.command(json!({"kind":"clear","devices":[crate::test_support::case::name("ade-serial")]}))
        .await?;
    c.cycle().await?;
    ensure!(
        c.enroll(machine.clone()).await?.0 != StatusCode::OK,
        "unassigned pending enrollment remained usable"
    );
    ensure!(
        old_device
            .enroll(
                &c.f.client()?,
                &c.f.app.apple()?.channel.scep_fixture()?.0,
                &old_csr
            )
            .await
            .is_err(),
        "old challenge survived unassignment"
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let prepared: bool = sqlx::query_scalar(
        "SELECT state='prepared' FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(old_attempt)
    .fetch_one(&mut pg)
    .await?;
    ensure!(prepared);
    sqlx::query("UPDATE mdm_access.requests SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(old_id).execute(&mut pg).await?;
    c.command(json!({"kind":"assign","profile":c.profile,"revision":1,"devices":[crate::test_support::case::name("ade-serial")]})).await?;
    c.cycle().await?;
    let fresh = c.enroll(machine).await?;
    ensure!(
        fresh.0 == StatusCode::OK,
        "expired pending could not be reissued"
    );
    let (id, attempt, challenge) = Control::coordinates(&fresh.1)?;
    ensure!(id != old_id && challenge != old_challenge);
    let device = scep_client::Device::new(id, attempt, &challenge)?;
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
    c.command(json!({"kind":"clear","devices":[crate::test_support::case::name("ade-serial")]}))
        .await?;
    c.cycle().await?;
    ensure!(
        c.f.authenticate_peer(&device, &der).await.is_err(),
        "first binding survived unassignment"
    );
    let pending: bool = sqlx::query_scalar(
        "SELECT state='pending' FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(id)
    .fetch_one(&mut pg)
    .await?;
    ensure!(pending);
    pg.close().await?;
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

#[tokio::test]
#[ignore = "MODULE=apple.ade: checkpoint, cursor reset, stale HTTP fencing and read-only recovery"]
async fn interrupted_snapshots_and_unknown_assignment_recover_without_false_publication()
-> Result<()> {
    let mut c = Control::start().await?;
    c.prepared_directory().await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let serial = crate::test_support::case::name("ade-serial");
    let next_serial = crate::test_support::case::name("ade-next-serial");
    c.state.lock().await.snapshot_serial = Some(next_serial.into());
    let op = c.command(json!({"kind":"sync","full":true})).await?;
    c.cycle().await?;
    let visible:bool=sqlx::query_scalar("SELECT NOT deleted FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3").bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(visible, "incomplete snapshot deleted an existing device");
    // Discard the worker handle and continue from a newly assembled durable reader.
    let resumed =
        crate::api::from_state(c.f.app.clone(), "mdm.example.test".into(), fixture_clock())
            .apple_control;
    c.state.lock().await.cursor_fail_once = true;
    ensure!(rss_mdm_apple_channel::ade::worker::cycle(&resumed).await?);
    let state = c.result(op).await?;
    ensure!(state["state"] == "pending" && state["result"]["reason"] == "cursor_reset");
    sqlx::query(
        "UPDATE mdm_apple.ade_operations SET next_attempt=0 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(op)
    .execute(&mut pg)
    .await?;
    ensure!(rss_mdm_apple_channel::ade::worker::cycle(&resumed).await?);
    ensure!(rss_mdm_apple_channel::ade::worker::cycle(&resumed).await?);
    ensure!(c.result(op).await?["state"] == "succeeded");
    let removed:bool=sqlx::query_scalar("SELECT deleted FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3").bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(removed);

    let gate = Arc::new(Gate::default());
    {
        let mut s = c.state.lock().await;
        s.snapshot_serial = Some(serial.into());
        s.block = Some(gate.clone());
        s.reject_session_once = true;
    }
    let stale = c.command(json!({"kind":"sync","full":true})).await?;
    let worker = c.f.ade.clone();
    let task =
        tokio::spawn(async move { rss_mdm_apple_channel::ade::worker::cycle(&worker).await });
    tokio::time::timeout(Duration::from_secs(10), gate.started.notified()).await?;
    c.f.browser.operation = Some(Uuid::new_v4());
    let changed=c.f.browser.call(&c.f.router,Method::PUT,&format!("{}/configuration",c.path()),Some(json!({"expectedRevision":1,"enabled":true,"serverUuid":c.organization,"orgId":"T2-organization","rotateKey":false}))).await?;
    ensure!(
        changed.0 == StatusCode::OK,
        "configuration was blocked behind external HTTP"
    );
    gate.release.notify_one();
    ensure!(task.await??);
    ensure!(c.result(stale).await?["state"] == "superseded");
    let still_removed:bool=sqlx::query_scalar("SELECT deleted FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3").bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(still_removed, "old HTTP published after authority changed");

    c.command(json!({"kind":"sync","full":true})).await?;
    c.cycle().await?;
    c.cycle().await?;
    c.state.lock().await.lose_assign = true;
    let assign = c
        .command(json!({"kind":"assign","profile":c.profile,"revision":1,"devices":[serial]}))
        .await?;
    c.cycle().await?;
    ensure!(
        c.result(assign).await?["state"] == "unknown",
        "HTML 500 after effect was treated as definite failure"
    );
    c.state.lock().await.details_fail_once = true;
    let recovery = c
        .command(json!({"kind":"reconcile","operation":assign}))
        .await?;
    c.cycle().await?;
    ensure!(
        c.result(recovery).await?["state"] == "pending",
        "read-only failure made a permanent unknown barrier"
    );
    sqlx::query(
        "UPDATE mdm_apple.ade_operations SET next_attempt=0 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(recovery)
    .execute(&mut pg)
    .await?;
    c.cycle().await?;
    ensure!(
        c.result(assign).await?["state"] == "succeeded"
            && c.result(recovery).await?["state"] == "succeeded"
    );
    let mut other = c.f.app.access.begin(&Uuid::new_v4().to_string()).await?;
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_apple.ade_devices")
        .fetch_one(&mut *other)
        .await?;
    ensure!(leaked == 0);
    other.rollback().await?;
    pg.close().await?;
    c.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.ade: definitive read recovery and per-device throttling"]
async fn unapplied_effect_releases_the_barrier_and_throttling_retries_only_pending_devices()
-> Result<()> {
    let mut c = Control::start().await?;
    c.prepared_directory().await?;
    let serial = crate::test_support::case::name("ade-serial");
    c.command(json!({"kind":"clear","devices":[serial]}))
        .await?;
    c.cycle().await?;
    c.state.lock().await.drop_assign_once = true;
    let lost = c
        .command(json!({"kind":"assign","profile":c.profile,"revision":1,"devices":[serial]}))
        .await?;
    c.cycle().await?;
    ensure!(c.result(lost).await?["state"] == "unknown");
    let query = c
        .command(json!({"kind":"reconcile","operation":lost}))
        .await?;
    c.cycle().await?;
    ensure!(c.result(query).await?["state"] == "succeeded");
    ensure!(c.result(lost).await?["state"] == "failed");
    let second = crate::test_support::case::name("ade-second-serial");
    c.state.lock().await.additional_serial = Some(second.into());
    c.command(json!({"kind":"sync","full":true})).await?;
    c.cycle().await?;
    c.cycle().await?;
    c.state.lock().await.throttle_assign_once = true;
    let op = c
        .command(
            json!({"kind":"assign","profile":c.profile,"revision":1,"devices":[serial,second]}),
        )
        .await?;
    c.cycle().await?;
    let pending = c.result(op).await?;
    ensure!(
        pending["state"] == "pending"
            && pending["result"]["devices"][serial] == "SUCCESS"
            && pending["result"]["devices"][second] == "THROTTLED"
    );
    ensure!(
        !rss_mdm_apple_channel::ade::worker::cycle(&c.f.ade).await?,
        "throttled assignment retried before its delay"
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let delay:i64=sqlx::query_scalar("SELECT next_attempt-created_at FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(op).fetch_one(&mut pg).await?;
    ensure!(delay >= 120);
    sqlx::query(
        "UPDATE mdm_apple.ade_operations SET next_attempt=0 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(op)
    .execute(&mut pg)
    .await?;
    c.cycle().await?;
    ensure!(c.result(op).await?["state"] == "succeeded");
    ensure!(
        c.state.lock().await.assignments.last() == Some(&vec![second.to_owned()]),
        "successful device was reassigned during throttling retry"
    );
    pg.close().await?;
    c.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.ade: incomplete observations cannot prove unassignment"]
async fn incomplete_observation_never_confirms_a_clear() -> Result<()> {
    let mut c = Control::start().await?;
    c.prepared_directory().await?;
    c.state.lock().await.drop_clear_once = true;
    let clear = c
        .command(json!({"kind":"clear","devices":[crate::test_support::case::name("ade-serial")]}))
        .await?;
    c.cycle().await?;
    ensure!(c.result(clear).await?["state"] == "unknown");
    c.state.lock().await.incomplete_details_once = true;
    let query = c
        .command(json!({"kind":"reconcile","operation":clear}))
        .await?;
    c.cycle().await?;
    ensure!(
        c.result(query).await?["state"] == "failed" && c.result(clear).await?["state"] == "unknown"
    );
    let machine = c.machine()?;
    ensure!(
        c.enroll(machine.clone()).await?.0 != StatusCode::OK,
        "unknown clear authorized a pending enrollment"
    );
    let query = c
        .command(json!({"kind":"reconcile","operation":clear}))
        .await?;
    c.cycle().await?;
    ensure!(
        c.result(query).await?["state"] == "succeeded"
            && c.result(clear).await?["state"] == "failed"
    );
    ensure!(
        c.enroll(machine.clone()).await?.0 == StatusCode::OK,
        "authoritative assignment was lost during clear recovery"
    );
    c.command(json!({"kind":"clear","devices":[crate::test_support::case::name("ade-serial")]}))
        .await?;
    c.cycle().await?;
    ensure!(c.enroll(machine).await?.0 != StatusCode::OK);
    c.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.ade: full snapshot authority after incremental cursor reset"]
async fn full_rebuild_replaces_newer_delta_state_and_revokes_stale_profile() -> Result<()> {
    let mut c = Control::start().await?;
    c.prepared_directory().await?;
    let machine = c.machine()?;
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::OK);
    let serial = crate::test_support::case::name("ade-serial");
    let remote = c.state.lock().await.profile;
    // Incremental operation dates order events, including duplicates delivered out of order.
    for (date, profile, cursor) in [
        ("2026-10-02T00:00:00.123456Z", Some(remote), "delta-new"),
        ("2026-10-01T00:00:00.123456Z", None, "delta-old"),
    ] {
        c.state.lock().await.sync_responses.push_back(json!({"devices":[{"serial_number":serial,"op_type":"modified","op_date":date,"profile_uuid":profile}],"cursor":cursor,"more_to_follow":false}));
        let op = c.command(json!({"kind":"sync","full":false})).await?;
        c.cycle().await?;
        ensure!(c.result(op).await?["state"] == "succeeded");
    }
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let before: (Option<Uuid>, String) = sqlx::query_as("SELECT remote_profile,operation_date::text FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3")
        .bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(before.0 == Some(remote) && before.1.starts_with("2026-10-02"));
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::OK);
    {
        let mut state = c.state.lock().await;
        state.assigned = false;
        state.cursor_fail_once = true;
    }
    let op = c.command(json!({"kind":"sync","full":false})).await?;
    c.cycle().await?;
    ensure!(c.result(op).await?["result"]["reason"] == "cursor_reset");
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::UNAUTHORIZED);
    sqlx::query(
        "UPDATE mdm_apple.ade_operations SET next_attempt=0 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(op)
    .execute(&mut pg)
    .await?;
    c.cycle().await?;
    let staged: Option<Uuid> = sqlx::query_scalar("SELECT remote_profile FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3")
        .bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(
        staged == Some(remote),
        "incomplete full snapshot was published"
    );
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::UNAUTHORIZED);
    c.cycle().await?;
    ensure!(c.result(op).await?["state"] == "succeeded");
    let current: (Option<Uuid>, String) = sqlx::query_as("SELECT remote_profile,operation_date::text FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3")
        .bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(
        current.0.is_none() && current.1.starts_with("2026-10-01"),
        "full assignment date was compared with the newer delta event date"
    );
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::UNAUTHORIZED);
    // A complete later snapshot also replaces the old local profile with another remote profile.
    let replacement = Uuid::new_v4();
    {
        let mut state = c.state.lock().await;
        state.profile = replacement;
        state.assigned = true;
    }
    let op = c.command(json!({"kind":"sync","full":true})).await?;
    c.cycle().await?;
    c.cycle().await?;
    ensure!(c.result(op).await?["state"] == "succeeded");
    let current: Option<Uuid> = sqlx::query_scalar("SELECT remote_profile FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3")
        .bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(current == Some(replacement));
    ensure!(c.enroll(machine).await?.0 == StatusCode::UNAUTHORIZED);
    pg.close().await?;
    c.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.ade: empty delta freshness, terminal cursor and broken-chain refusal"]
async fn unchanged_devices_remain_authoritative_until_the_directory_chain_breaks() -> Result<()> {
    let mut c = Control::start().await?;
    c.prepared_directory().await?;
    let serial = crate::test_support::case::name("ade-serial");
    let machine = c.machine()?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    // Eight days with no device changes; an old completed directory must first be refused.
    sqlx::query("UPDATE mdm_apple.ade_devices SET observed_at=floor(extract(epoch FROM clock_timestamp()))::bigint-691200 WHERE tenant_id=$1::uuid AND organization=$2")
        .bind(case_tenant()).bind(c.organization).execute(&mut pg).await?;
    sqlx::query("UPDATE mdm_apple.ade_servers SET synced_at=floor(extract(epoch FROM clock_timestamp()))::bigint-691200,next_sync=0 WHERE tenant_id=$1::uuid AND organization=$2")
        .bind(case_tenant()).bind(c.organization).execute(&mut pg).await?;
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::UNAUTHORIZED);
    c.state
        .lock()
        .await
        .sync_responses
        .push_back(json!({"devices":[],"cursor":"page-2","more_to_follow":false}));
    c.cycle().await?; // The actual automatic scheduler continues the existing cursor.
    let automatic: Uuid = sqlx::query_scalar("SELECT id FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND kind='sync' AND actor='service:apple-ade'")
        .bind(case_tenant()).bind(c.organization).fetch_one(&mut pg).await?;
    ensure!(c.result(automatic).await?["state"] == "succeeded");
    let unchanged: bool = sqlx::query_scalar("SELECT observed_at<floor(extract(epoch FROM clock_timestamp()))::bigint-604800 FROM mdm_apple.ade_devices WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3")
        .bind(case_tenant()).bind(c.organization).bind(serial).fetch_one(&mut pg).await?;
    ensure!(
        unchanged,
        "empty delta rewrote the device observation to fake freshness"
    );
    let clear = c
        .command(json!({"kind":"clear","devices":[serial]}))
        .await?;
    c.cycle().await?;
    ensure!(c.result(clear).await?["state"] == "succeeded");
    sqlx::query("UPDATE mdm_apple.ade_devices SET observed_at=floor(extract(epoch FROM clock_timestamp()))::bigint-691200 WHERE tenant_id=$1::uuid AND organization=$2")
        .bind(case_tenant()).bind(c.organization).execute(&mut pg).await?;
    let assign = c
        .command(json!({"kind":"assign","profile":c.profile,"revision":1,"devices":[serial]}))
        .await?;
    c.cycle().await?;
    ensure!(c.result(assign).await?["state"] == "succeeded");
    sqlx::query("UPDATE mdm_apple.ade_devices SET observed_at=floor(extract(epoch FROM clock_timestamp()))::bigint-691200 WHERE tenant_id=$1::uuid AND organization=$2")
        .bind(case_tenant()).bind(c.organization).execute(&mut pg).await?;
    let pending = c.enroll(machine.clone()).await?;
    ensure!(pending.0 == StatusCode::OK);
    c.state.lock().await.cursor_fail_once = true;
    let rebuild = c.command(json!({"kind":"sync","full":false})).await?;
    c.cycle().await?;
    ensure!(c.result(rebuild).await?["result"]["reason"] == "cursor_reset");
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::UNAUTHORIZED);
    sqlx::query(
        "UPDATE mdm_apple.ade_operations SET next_attempt=0 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(rebuild)
    .execute(&mut pg)
    .await?;
    c.cycle().await?;
    ensure!(c.enroll(machine.clone()).await?.0 == StatusCode::UNAUTHORIZED);
    c.cycle().await?;
    ensure!(c.result(rebuild).await?["state"] == "succeeded");
    let replay = c.enroll(machine.clone()).await?;
    ensure!(replay.0 == StatusCode::OK && replay.1 == pending.1);
    let completed: i64 = sqlx::query_scalar(
        "SELECT synced_at FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2",
    )
    .bind(case_tenant())
    .bind(c.organization)
    .fetch_one(&mut pg)
    .await?;
    c.state
        .lock()
        .await
        .sync_responses
        .push_back(json!({"devices":[],"cursor":"page-2","more_to_follow":true}));
    let looped = c.command(json!({"kind":"sync","full":false})).await?;
    c.cycle().await?;
    let result = c.result(looped).await?;
    ensure!(result["state"] == "failed" && result["result"]["reason"] == "cursor_no_progress");
    let after: i64 = sqlx::query_scalar(
        "SELECT synced_at FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2",
    )
    .bind(case_tenant())
    .bind(c.organization)
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        after == completed,
        "incomplete looping delta refreshed directory authority"
    );
    sqlx::query("UPDATE mdm_apple.ade_servers SET synced_at=floor(extract(epoch FROM clock_timestamp()))::bigint-691200 WHERE tenant_id=$1::uuid AND organization=$2")
        .bind(case_tenant()).bind(c.organization).execute(&mut pg).await?;
    ensure!(c.enroll(machine).await?.0 == StatusCode::UNAUTHORIZED);
    c.f.browser.operation = Some(Uuid::new_v4());
    let refused =
        c.f.browser
            .call(
                &c.f.router,
                Method::POST,
                &format!("{}/operations", c.path()),
                Some(json!({"kind":"clear","devices":[serial]})),
            )
            .await?;
    ensure!(refused.0 == StatusCode::CONFLICT);
    pg.close().await?;
    c.close().await
}
