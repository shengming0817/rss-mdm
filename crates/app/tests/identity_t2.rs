//! The production Router consumes a fixed real Identity candidate; no mock verifier or claims constructor.
use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use reqwest::{Client, Url};
use rss_mdm_app::config::Config;
use rss_mdm_inventory_postgres::InventoryReader;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tower::ServiceExt;
const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "/api/v1/devices/device-1";

fn command(args: &[&str], input: Option<&str>) -> Result<String> {
    let mut c = Command::new("docker");
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        c.stdin(Stdio::piped());
    }
    let mut child = c.spawn()?;
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    let result = child.wait_with_output()?;
    ensure!(result.status.success(), "owned fixture command failed");
    Ok(String::from_utf8(result.stdout)?)
}
fn pg(sql: &str) -> Result<String> {
    command(
        &[
            "exec",
            "-i",
            &std::env::var("MDM_TEST_PG_CONTAINER")?,
            "psql",
            "-X",
            "-U",
            "postgres",
            "-d",
            "mdm",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        Some(sql),
    )
}
fn count() -> Result<usize> {
    let result = command(
        &[
            "exec",
            &std::env::var("MDM_TEST_PRIVATE_CONTAINER")?,
            "wc",
            "-l",
            "/tmp/validation.log",
        ],
        None,
    )?;
    Ok(result.split_whitespace().next().unwrap().parse()?)
}
fn http(c: &Config) -> Result<Client> {
    Ok(Client::builder()
        .cookie_store(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            &c.identity.ca_file,
        )?)?)
        .build()?)
}
async fn post(
    web: &Client,
    origin: &str,
    path: &str,
    body: Value,
    csrf: Option<&str>,
) -> Result<Value> {
    let mut r = web
        .post(format!("{origin}{path}"))
        .header("Origin", origin)
        .header("X-Identity-Request", "1")
        .json(&body);
    if let Some(csrf) = csrf {
        r = r.header("X-CSRF-Token", csrf);
    }
    let r = r
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Identity HTTP unavailable"))?;
    ensure!(
        r.status().is_success(),
        "Identity fixture operation rejected: {}",
        r.status()
    );
    if r.status() == StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }
    Ok(r.json().await?)
}
async fn login_identity(
    c: &Config,
    origin: &str,
    login: &str,
    password: &str,
) -> Result<(Client, String)> {
    let web = http(c)?;
    let result = post(
        &web,
        origin,
        &format!("/api/v1/tenants/{TENANT}/login"),
        json!({"login":login,"password":password}),
        None,
    )
    .await?;
    Ok((web, result["csrf_token"].as_str().unwrap().into()))
}
async fn location(web: &Client, url: Url) -> Result<Url> {
    let response = web
        .get(url)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("OIDC redirect unavailable"))?;
    ensure!(
        response.status().is_redirection(),
        "OIDC redirect rejected: {}",
        response.status()
    );
    Ok(Url::parse(
        response
            .headers()
            .get("location")
            .ok_or_else(|| anyhow::anyhow!("missing redirect"))?
            .to_str()?,
    )?)
}
fn param(url: &Url, key: &str) -> Result<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| {
            let code = url
                .query_pairs()
                .find(|(k, _)| k == "error")
                .map(|(_, v)| match v.as_ref() {
                    "invalid_request" => "invalid_request",
                    "invalid_scope" => "invalid_scope",
                    "unauthorized_client" => "unauthorized_client",
                    "access_denied" => "access_denied",
                    _ => "unclassified",
                })
                .unwrap_or("none");
            anyhow::anyhow!("missing protocol parameter {key}; oauth error={code}")
        })
}
async fn authorize(web: &Client, origin: &str, csrf: &str, url: Url) -> Result<Url> {
    let login = location(web, url).await?;
    if login.host_str() == Some("mdm.example.test")
        && login.path() == "/auth/callback"
        && login.query_pairs().any(|(key, _)| key == "error")
    {
        return Ok(login);
    }
    let challenge = param(&login, "login_challenge")?;
    let flow = post(
        web,
        origin,
        "/api/v1/downstream/login",
        json!({"challenge":challenge}),
        None,
    )
    .await?;
    let accepted = post(
        web,
        origin,
        "/api/v1/downstream/login/accept",
        json!({"challenge":challenge,"flow":flow}),
        Some(csrf),
    )
    .await?;
    let consent = location(web, Url::parse(accepted["redirect_to"].as_str().unwrap())?).await?;
    let challenge = param(&consent, "consent_challenge")?;
    let flow = post(
        web,
        origin,
        "/api/v1/downstream/consent",
        json!({"challenge":challenge}),
        None,
    )
    .await?;
    let accepted = post(
        web,
        origin,
        "/api/v1/downstream/consent/accept",
        json!({"challenge":challenge,"flow":flow}),
        Some(csrf),
    )
    .await?;
    location(web, Url::parse(accepted["redirect_to"].as_str().unwrap())?).await
}
#[derive(Default, Clone)]
struct Browser {
    cookies: BTreeMap<String, String>,
    csrf: Option<String>,
    operation: Option<uuid::Uuid>,
}
impl Browser {
    async fn call(
        &mut self,
        app: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        self.call_headers(app, method, path, body, None).await
    }
    async fn call_headers(
        &mut self,
        app: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
        headers: Option<(&[&str], &[&str])>,
    ) -> Result<(StatusCode, Value)> {
        let mut request = Request::builder()
            .method(&method)
            .uri(path)
            .header("host", "mdm.example.test");
        if method == Method::POST {
            request = request
                .header("origin", "https://mdm.example.test")
                .header("x-mdm-request", "1");
        }
        if !self.cookies.is_empty() {
            request = request.header(
                "cookie",
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        if let Some(key) = self.operation {
            request = request.header("idempotency-key", key.to_string());
        }
        if let Some(csrf) = &self.csrf {
            request = request.header("x-csrf-token", csrf);
        }
        let body = match body {
            Some(value) => {
                request = request.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&value)?)
            }
            None => Body::empty(),
        };
        let mut request = request.body(body)?;
        if let Some((origins, markers)) = headers {
            request.headers_mut().remove("origin");
            request.headers_mut().remove("x-mdm-request");
            for origin in origins {
                request
                    .headers_mut()
                    .append("origin", axum::http::HeaderValue::from_str(origin)?);
            }
            for marker in markers {
                request
                    .headers_mut()
                    .append("x-mdm-request", axum::http::HeaderValue::from_str(marker)?);
            }
        }
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        ensure!(
            response
                .headers()
                .get("cache-control")
                .is_some_and(|v| v == "no-store")
        );
        for header in response.headers().get_all("set-cookie") {
            let text = header.to_str()?;
            ensure!(
                text.contains("Secure")
                    && text.contains("HttpOnly")
                    && text.contains("Path=/")
                    && !text.contains("Domain=")
            );
            let (k, v) = text.split(';').next().unwrap().split_once('=').unwrap();
            if v.is_empty() {
                self.cookies.remove(k);
            } else {
                self.cookies.insert(k.into(), v.into());
            }
        }
        let redirect = response
            .headers()
            .get("location")
            .map(|v| v.to_str().map(str::to_owned))
            .transpose()?;
        let bytes = response.into_body().collect().await?.to_bytes();
        let value = if let Some(redirect) = redirect {
            json!({"location":redirect})
        } else if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        if let Some(csrf) = value.get("csrf_token").and_then(Value::as_str) {
            self.csrf = Some(csrf.into());
        }
        Ok((status, value))
    }
    async fn callback(&mut self, app: &Router, url: &Url) -> Result<StatusCode> {
        Ok(self
            .call(
                app,
                Method::GET,
                &format!("{}?{}", url.path(), url.query().unwrap_or("")),
                None,
            )
            .await?
            .0)
    }
    async fn login(
        &mut self,
        app: &Router,
        web: &Client,
        origin: &str,
        csrf: &str,
    ) -> Result<StatusCode> {
        let (status, value) = self.call(app, Method::POST, "/auth/login", None).await?;
        ensure!(
            status == StatusCode::OK,
            "MDM login begin rejected: {status}"
        );
        let callback = authorize(
            web,
            origin,
            csrf,
            Url::parse(value["authorization_url"].as_str().unwrap())?,
        )
        .await?;
        let status = self.callback(app, &callback).await?;
        if status == StatusCode::SEE_OTHER {
            ensure!(
                self.call(app, Method::GET, "/api/v1/auth/me", None)
                    .await?
                    .0
                    == StatusCode::OK
            );
        }
        Ok(status)
    }
}
async fn access_store(value: &Value) -> Result<Arc<rss_mdm_app::AccessStore>> {
    let config: Config = serde_json::from_value(value.clone())?;
    Ok(Arc::new(
        rss_mdm_app::AccessStore::connect(config.access_database.options()?).await?,
    ))
}
async fn app(value: &Value, reader: Arc<InventoryReader>) -> Result<Router> {
    let c: Config = serde_json::from_value(value.clone())?;
    Ok(rss_mdm_app::application(
        c,
        Arc::new(rss_identity_client::SystemClock),
        monotonic(),
        reader,
        access_store(value).await?,
    )
    .await?)
}
// Pause the official SDK's post-response clock read, without replacing validation.
#[derive(Default)]
struct GateClock {
    state: std::sync::Mutex<(usize, bool)>,
    released: std::sync::Condvar,
    blocked: tokio::sync::Notify,
}
impl GateClock {
    fn arm(&self) {
        *self.state.lock().unwrap() = (3, false);
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.released.notify_all();
    }
}
impl rss_identity_client::Clock for GateClock {
    fn unix_seconds(&self) -> std::result::Result<i64, rss_identity_client::Error> {
        let mut state = self.state.lock().unwrap();
        if state.0 > 0 {
            state.0 -= 1;
            if state.0 == 0 {
                self.blocked.notify_one();
                while !state.1 {
                    // This synchronous SDK hook must yield the Tokio worker so PG audit
                    // I/O can progress while the identity response remains gated.
                    let (next, timeout) = tokio::task::block_in_place(|| {
                        self.released
                            .wait_timeout(state, Duration::from_secs(8))
                            .unwrap()
                    });
                    state = next;
                    if timeout.timed_out() {
                        return Err(rss_identity_client::Error::Unavailable);
                    }
                }
            }
        }
        rss_identity_client::Clock::unix_seconds(&rss_identity_client::SystemClock)
    }
}
struct ReleaseGate(Arc<GateClock>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn reads() -> Result<i64> {
    Ok(pg("SELECT coalesce(sum(calls),0)::bigint FROM test_probe.pg_stat_statements WHERE userid=(SELECT oid FROM pg_roles WHERE rolname='mdm_api') AND query LIKE 'SELECT field,value,batch_id,observed_at,received_at FROM mdm.inventory%'")?.trim().parse()?)
}
async fn session_races_and_admission(
    value: &Value,
    reader: Arc<InventoryReader>,
    web: &Client,
    origin: &str,
    csrf: &str,
    query: &str,
) -> Result<()> {
    let clock = Arc::new(GateClock::default());
    let router = rss_mdm_app::application(
        serde_json::from_value(value.clone())?,
        clock.clone(),
        monotonic(),
        reader,
        access_store(value).await?,
    )
    .await?;
    for replace in [false, true] {
        let mut browser = Browser::default();
        ensure!(browser.login(&router, web, origin, csrf).await? == StatusCode::SEE_OTHER);
        ensure!(browser.call(&router, Method::GET, query, None).await?.0 == StatusCode::OK);
        let before = reads()?;
        ensure!(
            before > 0,
            "inventory query counter did not observe actual reads"
        );
        let mut old = browser.clone();
        let r = router.clone();
        let q = query.to_owned();
        let guard = ReleaseGate(clock.clone());
        clock.arm();
        let task = tokio::spawn(async move { old.call(&r, Method::GET, &q, None).await });
        tokio::time::timeout(Duration::from_secs(5), clock.blocked.notified()).await?;
        let validated = count()?;
        ensure!(
            browser
                .call(&router, Method::GET, "/api/v1/auth/me", None)
                .await?
                .0
                == StatusCode::SERVICE_UNAVAILABLE,
            "session admission did not shed concurrent validation"
        );
        ensure!(count()? == validated, "shed request reached Identity");
        if replace {
            ensure!(browser.login(&router, web, origin, csrf).await? == StatusCode::SEE_OTHER);
        } else {
            ensure!(
                browser
                    .call(&router, Method::POST, "/api/v1/auth/logout", None)
                    .await?
                    .0
                    == StatusCode::NO_CONTENT
            );
        }
        drop(guard);
        ensure!(
            task.await??.0 == StatusCode::UNAUTHORIZED,
            "in-flight old session survived logout/replacement"
        );
        ensure!(
            reads()? == before,
            "revoked request reached inventory reader"
        );
    }
    let mut browsers = Vec::new();
    for _ in 0..5 {
        let mut b = Browser::default();
        ensure!(b.login(&router, web, origin, csrf).await? == StatusCode::SEE_OTHER);
        browsers.push(b);
    }
    let guard = ReleaseGate(clock.clone());
    let mut tasks = Vec::new();
    for browser in &browsers[..4] {
        let mut b = browser.clone();
        let r = router.clone();
        clock.arm();
        tasks.push(tokio::spawn(async move {
            b.call(&r, Method::GET, "/api/v1/auth/me", None).await
        }));
        tokio::time::timeout(Duration::from_secs(5), clock.blocked.notified()).await?;
    }
    let before = count()?;
    ensure!(
        browsers[4]
            .call(&router, Method::GET, "/api/v1/auth/me", None)
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE,
        "global admission not enforced"
    );
    ensure!(count()? == before, "global shed request reached Identity");
    drop(guard);
    for task in tasks {
        ensure!(task.await??.0 == StatusCode::OK);
    }
    ensure!(
        browsers[4]
            .call(&router, Method::GET, "/api/v1/auth/me", None)
            .await?
            .0
            == StatusCode::OK,
        "admission capacity did not recover"
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2-identity: approved Identity candidate and real providers"]
async fn real_identity_mdm_authorization_and_revocation() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(240), matrix()).await??;
    Ok(())
}
async fn matrix() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: Config = serde_json::from_value(base.clone())?;
    let origin = std::env::var("MDM_TEST_PUBLIC_ORIGIN")?;
    let password = std::fs::read_to_string(std::env::var("MDM_TEST_PASSWORD_FILE")?)?;
    let (admin, admin_csrf) = login_identity(&config, &origin, "admin", &password).await?;
    let account = post(
        &admin,
        &origin,
        &format!("/api/v1/tenants/{TENANT}/accounts"),
        json!({"login":"operator","password":password,"role":"member"}),
        Some(&admin_csrf),
    )
    .await?;
    let principal = account["principal_id"].as_str().unwrap().to_owned();
    let (web, central_csrf) = login_identity(&config, &origin, "operator", &password).await?;
    let reader = Arc::new(InventoryReader::connect(config.database.options()?).await?);
    let initial = app(&base, reader.clone()).await?;
    let mut browser = Browser::default();
    let (status, value) = browser
        .call(&initial, Method::POST, "/auth/login", None)
        .await?;
    ensure!(status == StatusCode::OK);
    let mut callback = authorize(
        &web,
        &origin,
        &central_csrf,
        Url::parse(value["authorization_url"].as_str().unwrap())?,
    )
    .await?;
    callback
        .query_pairs_mut()
        .append_pair("session_state", "opaque-extension");
    for (failure_code, expected) in [
        ("access_denied", StatusCode::UNAUTHORIZED),
        ("temporarily_unavailable", StatusCode::SERVICE_UNAVAILABLE),
        ("unknown_failure", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let mut declined = Browser::default();
        let (_, start) = declined
            .call(&initial, Method::POST, "/auth/login", None)
            .await?;
        let authorization = Url::parse(start["authorization_url"].as_str().unwrap())?;
        let mut failure = Url::parse("https://mdm.example.test/auth/callback")?;
        failure
            .query_pairs_mut()
            .append_pair("state", &param(&authorization, "state")?)
            .append_pair("error", failure_code)
            .append_pair("session_state", "extension");
        let before = count()?;
        ensure!(
            declined.callback(&initial, &failure).await? == expected,
            "extended OAuth error callback was malformed"
        );
        ensure!(
            count()? == before,
            "OAuth error callback reached validation"
        );
        ensure!(!declined.cookies.contains_key("__Host-mdm-session"));
    }
    ensure!(
        Browser::default().callback(&initial, &callback).await? == StatusCode::UNAUTHORIZED,
        "wrong browser accepted"
    );
    let mut wrong = callback.clone();
    wrong
        .query_pairs_mut()
        .clear()
        .append_pair("state", "wrong")
        .append_pair("code", &param(&callback, "code")?);
    ensure!(
        browser.callback(&initial, &wrong).await? == StatusCode::UNAUTHORIZED,
        "wrong state accepted"
    );
    ensure!(
        browser
            .call(
                &initial,
                Method::HEAD,
                &format!("{}?{}", callback.path(), callback.query().unwrap()),
                None
            )
            .await?
            .0
            == StatusCode::METHOD_NOT_ALLOWED,
        "HEAD consumed callback"
    );
    ensure!(browser.callback(&initial, &callback).await? == StatusCode::SEE_OTHER);
    ensure!(
        browser.callback(&initial, &callback).await? == StatusCode::UNAUTHORIZED,
        "callback replay accepted"
    );
    let (_, me) = browser
        .call(&initial, Method::GET, "/api/v1/auth/me", None)
        .await?;
    println!("identity matrix: initial PKCE login and callback protections passed");
    let subject = me["subject"].as_str().unwrap();
    ensure!(me["roles"] == json!([]));
    let query = format!("{DEVICE}/inventory?channel=mdm&source=mdm.windows");
    ensure!(browser.call(&initial, Method::GET, &query, None).await?.0 == StatusCode::FORBIDDEN);
    let mut damaged = Browser::default();
    damaged
        .cookies
        .insert("__Host-mdm-session".into(), "old-or-damaged-cookie".into());
    ensure!(
        damaged
            .call(&initial, Method::GET, "/api/v1/auth/me", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        damaged
            .login(&initial, &web, &origin, &central_csrf)
            .await?
            == StatusCode::SEE_OTHER,
        "invalid old cookie prevented login"
    );
    let mut allowed = base.clone();
    allowed["bindings"] = json!([{"tenant_id":TENANT,"client_id":"mdm","subject":subject,"roles":["super_admin"],"devices":["device-1"],"allow_wipe":true,"allow_enrollment":true,"allow_manage_credentials":false}]);
    let authorized = app(&allowed, reader.clone()).await?;
    // A stale product cookie after process restart must not trap the user outside login.
    ensure!(
        browser
            .login(&authorized, &web, &origin, &central_csrf)
            .await?
            == StatusCode::SEE_OTHER
    );
    let scope = serde_json::to_string(
        &json!({"tenant":TENANT,"object":"99999999-9999-4999-8999-999999999991","registration":"99999999-9999-4999-8999-999999999991","source":"mdm.windows","dataset":"inventory","epoch":"99999999-9999-4999-8999-999999999992"}),
    )?;
    // Use the public Scope encoder, not JSON map key order, for the persisted identity.
    let scope: rss_observation::Scope = serde_json::from_str(&scope)?;
    let encoded = scope.encode()?.replace('\'', "''");
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage())?;
    // Read-path fixture only. Device registration/credential proof is exercised by device PG T2.
    pg(&format!(
        r#"
        INSERT INTO mdm_access.grants(tenant_id,id,actor,client,device,purpose,state,expires_at) VALUES('{TENANT}','99999999-9999-4999-8999-999999999993','read-fixture','mdm','device-1','enrollment','consumed',clock_timestamp()+interval '200 seconds');
        INSERT INTO mdm_access.requests VALUES('{TENANT}','99999999-9999-4999-8999-999999999994','99999999-9999-4999-8999-999999999993');
        INSERT INTO mdm_access.devices VALUES('{TENANT}','device-1');
        INSERT INTO mdm_access.registrations VALUES('{TENANT}','99999999-9999-4999-8999-999999999991','device-1','mdm',1,'99999999-9999-4999-8999-999999999994','active');
        INSERT INTO mdm_access.credentials VALUES('{TENANT}','99999999-9999-4999-8999-999999999995','99999999-9999-4999-8999-999999999991','mdm',repeat('a',64),'active');
        INSERT INTO mdm_access.report_sources VALUES('{TENANT}','99999999-9999-4999-8999-999999999991','mdm.windows','99999999-9999-4999-8999-999999999992','{coverage}',true);
        INSERT INTO mdm.inventory VALUES('{TENANT}','mdm.observation.v1','inventory-v1','{encoded}','{coverage}','device.model','Model-A','fixture',1,2);
    "#
    ))?;
    let before = count()?;
    ensure!(
        browser
            .call(&authorized, Method::GET, "/api/v1/auth/me", None)
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        browser
            .call(&authorized, Method::GET, "/api/v1/auth/me", None)
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(count()? == before + 2, "identity success cached");
    let (status, assets) = browser.call(&authorized, Method::GET, &query, None).await?;
    ensure!(status == StatusCode::OK && assets["fields"][0]["value"] == "Model-A");
    ensure!(assets["tenant_id"] == TENANT);
    ensure!(assets["device_id"] == "device-1");
    ensure!(assets["registration"] == "99999999-9999-4999-8999-999999999991");
    ensure!(assets["source"] == "mdm.windows");
    ensure!(assets["epoch"] == "99999999-9999-4999-8999-999999999992");
    ensure!(assets["coverage"] == serde_json::to_value(rss_mdm_inventory::coverage())?);
    enrollment_matrix(
        &authorized,
        &allowed,
        reader.clone(),
        &mut browser,
        &web,
        &origin,
        &central_csrf,
        &query,
    )
    .await?;
    ensure!(
        browser
            .call(
                &authorized,
                Method::GET,
                &query.replace("source=mdm.windows", "source=missing"),
                None
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    ensure!(
        browser
            .call(
                &authorized,
                Method::GET,
                &query.replace("device-1", "device-other"),
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    for coordinate in [
        "tenant=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "registration=88888888-8888-4888-8888-888888888881",
        "epoch=88888888-8888-4888-8888-888888888882",
    ] {
        ensure!(
            browser
                .call(
                    &authorized,
                    Method::GET,
                    &format!("{query}&{coordinate}"),
                    None
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );
    }
    let rows = pg("SELECT count(*) FROM mdm.inventory;")?;
    let initial_cookies = browser.cookies.clone();
    let initial_validations = count()?;
    for path in [
        "/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/devices/device-1/actions",
    ] {
        for (origins, markers) in [
            (&[][..], &["1"][..]),
            (&["https://attacker.test"][..], &["1"][..]),
            (
                &["https://mdm.example.test", "https://attacker.test"][..],
                &["1"][..],
            ),
            (&["https://mdm.example.test"][..], &[][..]),
            (&["https://mdm.example.test"][..], &["wrong"][..]),
            (&["https://mdm.example.test"][..], &["1", "1"][..]),
        ] {
            ensure!(
                browser
                    .call_headers(
                        &authorized,
                        Method::POST,
                        path,
                        Some(json!({"action":"wipe"})),
                        Some((origins, markers))
                    )
                    .await?
                    .0
                    == StatusCode::FORBIDDEN,
                "invalid request origin/marker accepted"
            );
            ensure!(browser.cookies == initial_cookies);
        }
    }
    ensure!(
        count()? == initial_validations,
        "invalid origin caused remote authentication work"
    );

    ensure!(
        browser
            .call(
                &authorized,
                Method::POST,
                &format!("{DEVICE}/actions"),
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::NOT_IMPLEMENTED
    );
    let saved = browser.csrf.take();
    ensure!(
        browser
            .call(
                &authorized,
                Method::POST,
                &format!("{DEVICE}/actions"),
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    browser.csrf = saved;
    for role in [
        "super_admin",
        "mdm_admin",
        "security_admin",
        "help_desk",
        "auditor",
    ] {
        let mut v = allowed.clone();
        v["bindings"][0]["roles"] = json!([role]);
        v["bindings"][0]["allow_wipe"] = json!(false);
        v["bindings"][0]["allow_enrollment"] = json!(false);
        let scoped = app(&v, reader.clone()).await?;
        let mut b = Browser::default();
        ensure!(b.login(&scoped, &web, &origin, &central_csrf).await? == StatusCode::SEE_OTHER);
        ensure!(b.call(&scoped, Method::GET, &query, None).await?.0 == StatusCode::OK);
        ensure!(
            b.call(
                &scoped,
                Method::POST,
                &format!("{DEVICE}/actions"),
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0 == StatusCode::FORBIDDEN
        );
    }
    for role in ["super_admin", "mdm_admin"] {
        let mut v = allowed.clone();
        v["bindings"][0]["roles"] = json!([role]);
        let scoped = app(&v, reader.clone()).await?;
        let mut b = Browser::default();
        ensure!(b.login(&scoped, &web, &origin, &central_csrf).await? == StatusCode::SEE_OTHER);
        ensure!(
            b.call(
                &scoped,
                Method::POST,
                &format!("{DEVICE}/actions"),
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0 == StatusCode::NOT_IMPLEMENTED,
            "explicit administrator wipe permission rejected"
        );
    }
    ensure!(
        pg("SELECT count(*) FROM mdm.inventory;")? == rows,
        "device action wrote business data"
    );
    println!("identity matrix: role/device/Origin/CSRF/query/501 cases passed");
    for (field, value) in [
        ("audience", "wrong-api"),
        ("tenant_id", "22222222-2222-4222-8222-222222222222"),
    ] {
        let mut v = base.clone();
        v["identity"][field] = json!(value);
        let wrong = app(&v, reader.clone()).await?;
        let status = Browser::default()
            .login(&wrong, &web, &origin, &central_csrf)
            .await?;
        ensure!(
            status.is_client_error() || status.is_server_error(),
            "wrong identity binding accepted"
        );
    }
    // Separate service credentials are operational failures, never an anonymous fallback.
    let invalid_secret = std::path::Path::new(&config.identity.oidc_secret_file)
        .with_file_name("invalid-service-secret");
    std::fs::write(
        &invalid_secret,
        "invalid-service-credential-xxxxxxxxxxxxxxxx",
    )?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&invalid_secret, std::fs::Permissions::from_mode(0o600))?;
    for field in ["validation_secret_file", "oidc_secret_file"] {
        let mut value = base.clone();
        value["identity"][field] = json!(invalid_secret);
        let wrong = app(&value, reader.clone()).await?;
        let mut browser = Browser::default();
        ensure!(
            browser.login(&wrong, &web, &origin, &central_csrf).await?
                == StatusCode::SERVICE_UNAVAILABLE,
            "invalid service credential did not fail closed as 503"
        );
        ensure!(
            !browser.cookies.contains_key("__Host-mdm-session"),
            "failed exchange issued a session"
        );
    }
    std::fs::remove_file(invalid_secret)?;
    let mut other = Browser::default();
    let (_, start) = other
        .call(&authorized, Method::POST, "/auth/login", None)
        .await?;
    let mut url = Url::parse(start["authorization_url"].as_str().unwrap())?;
    let pairs: Vec<_> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs.into_iter().map(|(k, v)| {
            let value = match k.as_str() {
                "client_id" => "mdm-other".into(),
                "audience" => "other-api".into(),
                _ => v,
            };
            (k, value)
        }));
    let callback = authorize(&web, &origin, &central_csrf, url).await?;
    ensure!(
        other.callback(&authorized, &callback).await? == StatusCode::UNAUTHORIZED,
        "foreign client code accepted"
    );
    let mut bad_nonce = Browser::default();
    let (_, start) = bad_nonce
        .call(&authorized, Method::POST, "/auth/login", None)
        .await?;
    let mut url = Url::parse(start["authorization_url"].as_str().unwrap())?;
    let pairs: Vec<_> = url
        .query_pairs()
        .map(|(key, value)| {
            let value = if key == "nonce" {
                "tampered-nonce".into()
            } else {
                value.into_owned()
            };
            (key.into_owned(), value)
        })
        .collect();
    url.query_pairs_mut().clear().extend_pairs(pairs);
    let callback = authorize(&web, &origin, &central_csrf, url).await?;
    ensure!(
        bad_nonce.callback(&authorized, &callback).await? == StatusCode::UNAUTHORIZED,
        "wrong nonce accepted"
    );
    session_races_and_admission(
        &allowed,
        reader.clone(),
        &web,
        &origin,
        &central_csrf,
        &query,
    )
    .await?;
    for property in ["enabled", "membership"] {
        post(
            &admin,
            &origin,
            &format!("/api/v1/tenants/{TENANT}/accounts/{principal}/{property}"),
            json!({"enabled":false}),
            Some(&admin_csrf),
        )
        .await?;
        ensure!(
            browser
                .call(&authorized, Method::GET, &query, None)
                .await?
                .0
                == StatusCode::UNAUTHORIZED,
            "revoked identity accepted"
        );
        browser.operation = Some(uuid::Uuid::new_v4());
        ensure!(
            browser
                .call(
                    &authorized,
                    Method::POST,
                    "/api/v1/enrollment-grants",
                    Some(json!({"device_id":"device-1"}))
                )
                .await?
                .0
                == StatusCode::UNAUTHORIZED,
            "revoked identity issued grant"
        );
        browser.operation = None;

        post(
            &admin,
            &origin,
            &format!("/api/v1/tenants/{TENANT}/accounts/{principal}/{property}"),
            json!({"enabled":true}),
            Some(&admin_csrf),
        )
        .await?;
        ensure!(
            browser
                .call(&authorized, Method::GET, &query, None)
                .await?
                .0
                == StatusCode::UNAUTHORIZED,
            "old grant resurrected"
        );
        ensure!(
            browser
                .call(&authorized, Method::POST, "/api/v1/auth/logout", None)
                .await?
                .0
                == StatusCode::NO_CONTENT
        );
        let (fresh, csrf) = login_identity(&config, &origin, "operator", &password).await?;
        ensure!(browser.login(&authorized, &fresh, &origin, &csrf).await? == StatusCode::SEE_OTHER);
    }
    let (fresh, csrf) = login_identity(&config, &origin, "operator", &password).await?;
    let mut b = Browser::default();
    ensure!(b.login(&authorized, &fresh, &origin, &csrf).await? == StatusCode::SEE_OTHER);
    post(
        &fresh,
        &origin,
        &format!("/api/v1/tenants/{TENANT}/session/logout"),
        json!({}),
        Some(&csrf),
    )
    .await?;
    ensure!(
        b.call(&authorized, Method::GET, &query, None).await?.0 == StatusCode::UNAUTHORIZED,
        "central logout not observed"
    );
    let hydra = std::env::var("MDM_TEST_HYDRA_CONTAINER")?;
    command(&["pause", &hydra], None)?;
    let rejected = browser.call(&authorized, Method::GET, &query, None).await?;
    command(&["unpause", &hydra], None)?;
    ensure!(
        rejected.0 == StatusCode::SERVICE_UNAVAILABLE,
        "Hydra failure did not fail closed"
    );
    let identity = std::env::var("MDM_TEST_IDENTITY_CONTAINER")?;
    command(&["stop", "-t", "5", &identity], None)?;
    ensure!(
        browser
            .call(&authorized, Method::GET, &query, None)
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let before = count()?;
    ensure!(
        browser
            .call(&authorized, Method::POST, "/api/v1/auth/logout", None)
            .await?
            .0
            == StatusCode::NO_CONTENT
    );
    ensure!(count()? == before, "local logout contacted Identity");
    ensure!(
        browser
            .call(&authorized, Method::GET, &query, None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    reader.close().await;
    println!("MDM_IDENTITY_MATRIX_PASSED");
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "test composition root selects the real monotonic provider"
)]
fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(rss_mdm_app::Monotonic(std::time::Instant::now))
}

#[allow(clippy::too_many_arguments)]
async fn enrollment_matrix(
    router: &Router,
    config: &Value,
    reader: Arc<InventoryReader>,
    browser: &mut Browser,
    web: &Client,
    origin: &str,
    csrf: &str,
    query: &str,
) -> Result<()> {
    let issue = "/api/v1/enrollment-grants";
    let mut enrollment_only = config.clone();
    enrollment_only["bindings"][0]["allow_wipe"] = json!(false);
    let enrollment_router = app(&enrollment_only, reader.clone()).await?;
    let mut enrollment_browser = Browser::default();
    ensure!(
        enrollment_browser
            .login(&enrollment_router, web, origin, csrf)
            .await?
            == StatusCode::SEE_OTHER
    );
    ensure!(
        enrollment_browser
            .call(
                &enrollment_router,
                Method::POST,
                &format!("{DEVICE}/actions"),
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "enrollment permission authorized wipe"
    );
    enrollment_browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        enrollment_browser
            .call(
                &enrollment_router,
                Method::POST,
                issue,
                Some(json!({"device_id":"device-1"}))
            )
            .await?
            .0
            == StatusCode::OK
    );

    browser.operation = Some(uuid::Uuid::new_v4());
    let (status, grant) = browser
        .call(
            router,
            Method::POST,
            issue,
            Some(json!({"device_id":"device-1"})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "enrollment issue failed: {status} {grant}"
    );
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                issue,
                Some(json!({"device_id":"device-1"}))
            )
            .await?
            .1
            == grant,
        "issue replay changed result"
    );
    let permit = grant["grant_id"].clone();
    browser.operation = Some(uuid::Uuid::new_v4());
    let (_, accepted) = browser
        .call(
            router,
            Method::POST,
            "/api/v1/registration-requests",
            Some(json!({"device_id":"device-1","grant_id":permit})),
        )
        .await?;
    ensure!(accepted["status"] == "accepted");
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                "/api/v1/registration-requests",
                Some(json!({"device_id":"device-1","grant_id":permit}))
            )
            .await?
            .1
            == accepted
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                "/api/v1/registration-requests",
                Some(json!({"device_id":"device-1","grant_id":permit}))
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                issue,
                Some(json!({"device_id":"outside"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let (_, unused) = browser
        .call(
            router,
            Method::POST,
            issue,
            Some(json!({"device_id":"device-1"})),
        )
        .await?;
    let mut no_permission = config.clone();
    no_permission["bindings"][0]["allow_enrollment"] = json!(false);
    let restarted = app(&no_permission, reader).await?;
    let mut denied = Browser::default();
    ensure!(denied.login(&restarted, web, origin, csrf).await? == StatusCode::SEE_OTHER);
    denied.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        denied
            .call(
                &restarted,
                Method::POST,
                "/api/v1/registration-requests",
                Some(json!({"device_id":"device-1","grant_id":unused["grant_id"]}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    // Audit is mandatory for both reads and denied requests; never disclose assets on failure.
    pg("REVOKE INSERT ON mdm_access.audit FROM mdm_access")?;
    let read = browser.call(router, Method::GET, query, None).await?;
    let mut anonymous = Browser::default();
    let denied = anonymous.call(router, Method::GET, query, None).await?;
    pg("GRANT INSERT ON mdm_access.audit TO mdm_access")?;
    ensure!(read.0 == StatusCode::SERVICE_UNAVAILABLE && read.1.get("fields").is_none());
    ensure!(denied.0 == StatusCode::SERVICE_UNAVAILABLE);
    browser.operation = None;
    ensure!(browser.call(router, Method::GET, query, None).await?.0 == StatusCode::OK);
    let mut anonymous = Browser::default();
    ensure!(
        anonymous
            .call(
                router,
                Method::POST,
                issue,
                Some(json!({"device_id":"device-1"}))
            )
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(pg("SELECT count(*) FROM mdm_access.audit WHERE action='grant_issue' AND result='denied' AND actor IS NULL")?.trim().parse::<i64>()?>0,"preauthentication denial lost action");
    println!("enrollment identity/authorization/replay/audit failure matrix passed");
    Ok(())
}
