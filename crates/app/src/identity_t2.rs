#![allow(
    clippy::cognitive_complexity,
    reason = "sequential integration matrices preserve each failure and recovery assertion; production code remains checked"
)]
//! Real MDM Router with its own PG authority and native component HTTP routes.
mod assets;
mod authorization;
mod management;
#[allow(dead_code)]
#[path = "../tests/publication_support/mod.rs"]
mod publication_support;
#[cfg(feature = "integration")]
mod sso;
use crate::config::Config;
use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use reqwest::Client;
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
    ensure!(
        result.status.success(),
        "owned fixture command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn pg(sql: &str) -> Result<String> {
    pg_tenant(TENANT, sql)
}
fn pg_tenant(tenant: &str, sql: &str) -> Result<String> {
    uuid::Uuid::parse_str(tenant)?;
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
            "mdm_test",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        Some(&format!(
            "BEGIN; SET LOCAL rss.tenant_id='{tenant}'; {sql}; COMMIT;"
        )),
    )
}
use crate::identity_fixture::{ADMIN, INSTANCE, PASSWORD};
#[derive(Default, Clone)]
pub(crate) struct Browser {
    pub(crate) network: Option<(Client, String)>,
    cookies: BTreeMap<String, String>,
    csrf: Option<String>,
    operation: Option<uuid::Uuid>,
}
impl Browser {
    pub(crate) async fn call(
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
        if !method.is_safe() {
            request = request
                .header("origin", "https://mdm.example.test")
                .header("x-identity-request", "1");
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
            request.headers_mut().remove("x-identity-request");
            for origin in origins {
                request
                    .headers_mut()
                    .append("origin", axum::http::HeaderValue::from_str(origin)?);
            }
            for marker in markers {
                request.headers_mut().append(
                    "x-identity-request",
                    axum::http::HeaderValue::from_str(marker)?,
                );
            }
        }
        let response = if let Some((client, origin)) = &self.network {
            let (parts, body) = request.into_parts();
            let body = body.collect().await?.to_bytes();
            let response = client
                .request(parts.method, format!("{origin}{}", parts.uri))
                .headers(parts.headers)
                .body(body)
                .send()
                .await?;
            let status = response.status();
            let headers = response.headers().clone();
            let mut output = axum::response::Response::new(Body::from(response.bytes().await?));
            *output.status_mut() = status;
            *output.headers_mut() = headers;
            output
        } else {
            // Match a served request's task boundary: do not nest the complete
            // TLS/SQL/Router poll stack inside the multi-phase test future.
            tokio::spawn(app.clone().oneshot(request)).await??
        };
        let status = response.status();
        if method == Method::GET && path.contains("/collection-runs/") {
            ensure!(
                !response.headers().contains_key("idempotency-key"),
                "ordinary collection GET claimed an idempotent operation"
            );
        }
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
        if let Some(csrf) = value.get("csrfToken").and_then(Value::as_str) {
            self.csrf = Some(csrf.into());
        }
        Ok((status, value))
    }
    async fn login(&mut self, app: &Router, login: &str) -> Result<StatusCode> {
        self.login_password(app, login, crate::identity_fixture::PASSWORD)
            .await
    }
    async fn login_password(
        &mut self,
        app: &Router,
        login: &str,
        password: &str,
    ) -> Result<StatusCode> {
        Ok(self
            .call(
                app,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/login"),
                Some(json!({"login":login,"password":password})),
            )
            .await?
            .0)
    }
}
async fn access_store(value: &Value) -> Result<Arc<crate::AccessStore>> {
    let config: Config = serde_json::from_value(value.clone())?;
    Ok(Arc::new(
        crate::AccessStore::connect(config.access_database.options()?).await?,
    ))
}
async fn app(value: &Value, _reader: Arc<InventoryReader>) -> Result<Router> {
    app_with_access(value, access_store(value).await?).await
}
async fn app_with_access(value: &Value, access: Arc<crate::AccessStore>) -> Result<Router> {
    let c: Config = serde_json::from_value(value.clone())?;
    Ok(crate::api::application(
        c,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
    )
    .await
    .map_err(|error| anyhow::anyhow!("fixture application admission: {error:?}"))?
    .layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    ))))
}

fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(|| {
        rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
    }))
}

async fn start_automation(value: &Value) -> Result<rss_runtime::ShutdownStack> {
    let config: Config = serde_json::from_value(value.clone())?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    let service = config
        .management
        .open(
            rss_request_context::TenantId::parse(TENANT)?,
            Arc::new(crate::clock::SystemClock),
            |resource| startup.stage_resource(rss_runtime::DynManagedResource::new_box(resource)),
        )
        .await?;
    let automation =
        crate::management::automation::Automation::open(service, &config.management.database)
            .await?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::management::automation::Resource(automation.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(automation.registration().critical());
    launch.finish();
    Ok(stack)
}

async fn await_task(browser: &mut Browser, router: &Router, path: &str) -> Result<Value> {
    let mut last = Value::Null;
    let settled = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let (status, value) = browser.call(router, Method::GET, path, None).await?;
            if status == StatusCode::SERVICE_UNAVAILABLE {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            ensure!(status == StatusCode::OK, "task {path}: {status} {value}");
            last = value.clone();
            let state = if value.get("asset").is_some() {
                &value["asset"]
            } else {
                &value
            };
            if state["status"] == "completed" {
                return Ok(value);
            }
            ensure!(state["failure"].is_null(), "task {path} failed: {value}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    match settled {
        Ok(result) => result,
        Err(_) => {
            let progress = pg(&format!(
                "SELECT coalesce(jsonb_agg(p),'[]') FROM (SELECT j.id,j.kind,j.forwarded,j.failure,r.phase AS group_phase,r.object_count,s.phase AS scope_phase FROM mdm_management.automation_jobs j LEFT JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(j.tenant_id,j.id) LEFT JOIN mdm_management.scope_runs s ON (s.tenant_id,s.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{TENANT}' AND NOT j.completed ORDER BY j.id LIMIT 16)p"
            ))?;
            anyhow::bail!("task {path} exceeded fixture deadline; last {last}; pending {progress}")
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn enrollment_matrix(
    router: &Router,
    config: &Value,
    reader: Arc<InventoryReader>,
    browser: &mut Browser,
    query: &str,
) -> Result<()> {
    let issue = "/api/v2/enrollments";
    let enrollment_only = config.clone();
    set_device_grants(
        browser,
        router,
        "device-1",
        &["inventory_read", "enrollment"],
    )
    .await?;
    let enrollment_router = app(&enrollment_only, reader.clone()).await?;
    let mut enrollment_browser = browser.clone();
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
                Some(json!({"deviceId":"device-1","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","channel":"mdm"}))
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
            Some(json!({"deviceId":"device-1","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","channel":"mdm"})),
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
                Some(json!({"deviceId":"device-1","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","channel":"mdm"}))
            )
            .await?
            .1
            == grant,
        "issue replay changed result"
    );
    let enrollment = grant["enrollmentId"].as_str().unwrap();
    let status_path = format!("/api/v2/enrollments/{enrollment}");
    let current = browser
        .call(router, Method::GET, &status_path, None)
        .await?;
    ensure!(
        current.0 == StatusCode::OK
            && current.1["status"] == "pending"
            && current.1["registrationId"].is_null()
    );
    let resume = format!("/api/v2/enrollments/{enrollment}/resume");
    browser.operation = Some(uuid::Uuid::new_v4());
    let (_, resumed) = browser
        .call(
            router,
            Method::POST,
            &resume,
            Some(json!({"password": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"})),
        )
        .await?;
    ensure!(resumed["status"] == "pending");
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                &resume,
                Some(json!({"password":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}))
            )
            .await?
            .1
            == resumed
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(browser.call(router, Method::POST, issue, Some(json!({"deviceId":"outside","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","channel":"mdm"}))).await?.0 == StatusCode::FORBIDDEN);
    let no_permission = config.clone();
    set_device_grants(browser, router, "device-1", &["inventory_read"]).await?;
    let restarted = app(&no_permission, reader.clone()).await?;
    let mut denied = Browser::default();
    ensure!(denied.login(&restarted, "other").await? == StatusCode::OK);
    denied.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        denied
            .call(
                &restarted,
                Method::POST,
                &resume,
                Some(json!({"password":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    set_device_grants(
        browser,
        router,
        "device-1",
        &["inventory_read", "enrollment"],
    )
    .await?;
    let cancel = format!("/api/v2/enrollments/{enrollment}/cancel");
    let (status, cancelled) = browser
        .call(router, Method::POST, &cancel, Some(json!({})))
        .await?;
    ensure!(
        browser
            .call(router, Method::GET, &status_path, None)
            .await?
            .1["status"]
            == "cancelled"
    );
    ensure!(status == StatusCode::OK && cancelled["status"] == "cancelled");
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                &resume,
                Some(json!({"password":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"}))
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    // Audit is mandatory for both reads and denied requests; never disclose assets on failure.
    pg("REVOKE INSERT ON mdm_access.audit FROM mdm_access,mdm_management_runtime")?;
    let read = browser.call(router, Method::GET, query, None).await?;
    let mut anonymous = Browser::default();
    let denied = anonymous.call(router, Method::GET, query, None).await?;
    pg("GRANT INSERT ON mdm_access.audit TO mdm_access,mdm_management_runtime")?;
    ensure!(read.0 == StatusCode::SERVICE_UNAVAILABLE && read.1.get("asset").is_none());
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
                Some(json!({"deviceId":"device-1","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","channel":"mdm"}))
            )
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(pg("SELECT count(*) FROM mdm_access.audit WHERE action='enrollment_create' AND result='denied' AND actor IS NULL")?.trim().parse::<i64>()?>0,"preauthentication denial lost action");
    revoke_http_matrix(config, reader, browser).await?;
    println!("enrollment identity/authorization/replay/audit failure matrix passed");
    Ok(())
}

async fn agent_call(
    router: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mdm.example.test");
    if let Some(secret) = bearer {
        request = request.header("authorization", format!("Bearer {secret}"));
    }
    let body = if let Some(value) = body {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&value)?)
    } else {
        Body::empty()
    };
    let response = tokio::spawn(router.clone().oneshot(request.body(body)?)).await??;
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = response.into_body().collect().await?.to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    if status.is_client_error() || status.is_server_error() {
        ensure!(
            content_type.as_deref() == Some("application/json"),
            "Agent error escaped JSON content type: {status} {content_type:?}"
        );
        ensure!(
            value
                .as_object()
                .is_some_and(|body| body.len() == 1 && body["code"].is_string()),
            "Agent error escaped closed ErrorBody: {status} {value}"
        );
    }
    Ok((status, value))
}

async fn wait_agent_status(
    router: &Router,
    credential: &str,
    report_id: uuid::Uuid,
    observation: &str,
    projection: &str,
) -> Result<Value> {
    let mut last = Value::Null;
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (status, body) = agent_call(
                router,
                Method::GET,
                &format!("/api/agent/v1/reports/{report_id}"),
                Some(credential),
                None,
            )
            .await?;
            ensure!(
                status == StatusCode::OK,
                "Agent status failed: {status} {body}"
            );
            if body["observation"] == observation && body["projection"] == projection {
                return Ok::<_, anyhow::Error>(body);
            }
            last = body;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    settled.map_err(|_| {
        anyhow::anyhow!(
            "Agent report {report_id} did not settle at {observation}/{projection}; last={last}"
        )
    })?
}

async fn agent_runtime(config: &Value) -> Result<Arc<crate::inventory_runtime::InventoryRuntime>> {
    let access = access_store(config).await?;
    let config: Config = serde_json::from_value(config.clone())?;
    Ok(crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access,
        rss_request_context::TenantId::parse(TENANT)?,
        monotonic(),
    )
    .await?)
}

async fn agent_matrix(
    router: &Router,
    config: &Value,
    access: &Arc<crate::AccessStore>,
    browser: &mut Browser,
) -> Result<()> {
    let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let credential = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    browser.operation = Some(uuid::Uuid::new_v4());
    let (status, enrollment) = browser
        .call(
            router,
            Method::POST,
            "/api/v2/enrollments",
            Some(json!({"deviceId":"device-1","password":password,"channel":"agent"})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK && enrollment["channel"] == "agent",
        "Agent enrollment failed: {status} {enrollment}"
    );
    ensure!(
        browser
            .call(router, Method::POST, "/api/v1/enrollments", Some(json!({})))
            .await?
            .0
            == StatusCode::NOT_FOUND,
        "removed enrollment V1 remained reachable"
    );
    let operation = uuid::Uuid::new_v4();
    let registration_request = json!({
        "wireVersion":1,
        "operationId":operation,
        "enrollmentId":enrollment["enrollmentId"],
        "password":password,
        "credential":credential,
        "capabilities":["inventory.basic.v1"]
    });
    let (status, registration) = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/registrations",
        None,
        Some(registration_request.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::CREATED && registration["source"] == "agent.builtin",
        "Agent registration failed: {status} {registration}"
    );
    let (status, error) = agent_call(
        router,
        Method::GET,
        "/api/agent/v1/reports/not-a-uuid",
        Some(credential),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && error["code"] == "malformed_request",
        "invalid report path escaped the wire error contract: {status} {error}"
    );
    let (status, error) = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/reports",
        Some(credential),
        Some(json!({"oversized":"x".repeat(17_000)})),
    )
    .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && error["code"] == "malformed_request",
        "oversized body escaped the wire error contract: {status} {error}"
    );
    let (status, error) = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/reports",
        Some(credential),
        Some(json!({"oversized":"x".repeat(2 * 1024 * 1024 + 1)})),
    )
    .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && error["code"] == "malformed_request",
        ">2 MiB body escaped the Agent wire boundary: {status} {error}"
    );
    let mut unsupported_wire = registration_request.clone();
    unsupported_wire["wireVersion"] = json!(2);
    let response = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/registrations",
        None,
        Some(unsupported_wire),
    )
    .await?;
    ensure!(response == (StatusCode::BAD_REQUEST, json!({"code":"unsupported_wire"})));
    let mut unsupported_capability = registration_request.clone();
    unsupported_capability["capabilities"] = json!(["future"]);
    let response = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/registrations",
        None,
        Some(unsupported_capability),
    )
    .await?;
    ensure!(
        response
            == (
                StatusCode::BAD_REQUEST,
                json!({"code":"unsupported_capability"})
            )
    );
    ensure!(
        agent_call(
            router,
            Method::POST,
            "/api/agent/v1/registrations",
            None,
            Some(registration_request)
        )
        .await?
        .0 == StatusCode::OK,
        "registration replay was not recovered"
    );
    let missing = uuid::Uuid::new_v4();
    ensure!(
        agent_call(
            router,
            Method::GET,
            &format!("/api/agent/v1/reports/{missing}"),
            Some(credential),
            None
        )
        .await?
            == (StatusCode::NOT_FOUND, json!({"code":"report_not_found"}))
    );
    ensure!(
        agent_call(
            router,
            Method::GET,
            &format!("/api/agent/v1/reports/{missing}"),
            Some(password),
            None
        )
        .await?
            == (StatusCode::UNAUTHORIZED, json!({"code":"invalid_identity"}))
    );
    let report_id = uuid::Uuid::new_v4();
    let report = json!({
        "wireVersion":1,
        "reportId":report_id,
        "sequence":0,
        "observedAt":1,
        "body":{"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"known","value":"Agent Model"}},
            {"field":"device.os.version","value":{"kind":"known","value":"1.0"}}
        ]}
    });
    let (status, ack) = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/reports",
        Some(credential),
        Some(report.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED && ack["intake"] == "durable",
        "Agent report failed: {status} {ack}"
    );
    ensure!(
        agent_call(
            router,
            Method::POST,
            "/api/agent/v1/reports",
            Some(credential),
            Some(report.clone())
        )
        .await?
        .1 == ack,
        "report replay changed acknowledgement"
    );
    let concurrent_id = uuid::Uuid::new_v4();
    let concurrent = json!({"wireVersion":1,"reportId":concurrent_id,"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"temporarilyUnavailable"}});
    let mut same_id = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let router = router.clone();
        let body = concurrent.clone();
        same_id.spawn(async move {
            agent_call(
                &router,
                Method::POST,
                "/api/agent/v1/reports",
                Some(credential),
                Some(body),
            )
            .await
        });
    }
    let mut concurrent_ack = None;
    while let Some(result) = same_id.join_next().await {
        let result = result??;
        ensure!(result.0 == StatusCode::ACCEPTED);
        if let Some(expected) = &concurrent_ack {
            ensure!(
                &result.1 == expected,
                "concurrent replay changed acknowledgement"
            );
        } else {
            concurrent_ack = Some(result.1);
        }
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{concurrent_id}'"))?.trim() == "1", "concurrent replay duplicated durable intake");
    pg(&format!(
        "UPDATE mdm_access.collection_runs SET delivery_pending=false WHERE tenant_id='{TENANT}' AND id='{concurrent_id}'"
    ))?;
    let mut changed = report;
    changed["sequence"] = json!(1);
    ensure!(
        agent_call(
            router,
            Method::POST,
            "/api/agent/v1/reports",
            Some(credential),
            Some(changed)
        )
        .await?
        .0 == StatusCode::CONFLICT,
        "changed report identity was accepted"
    );
    let (status, current) = agent_call(
        router,
        Method::GET,
        &format!("/api/agent/v1/reports/{report_id}"),
        Some(credential),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && current["observation"] == "pending"
            && current["projection"] == "pending",
        "unexpected pre-worker status: {status} {current}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND source='agent.builtin' AND id='{report_id}' AND delivery_pending"))?.trim() == "1");
    let runtime = agent_runtime(config).await?;
    let owner = crate::inventory_runtime::tests::start(runtime.clone()).await?;
    wait_agent_status(router, credential, report_id, "snapshot", "applied").await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND source='agent.builtin' AND id='{report_id}' AND NOT delivery_pending"))?.trim() == "1");
    ensure!(pg(&format!("SELECT string_agg(field||'='||coalesce(value,''),',' ORDER BY field) FROM mdm.inventory WHERE tenant_id='{TENANT}' AND batch_id='{report_id}'"))?.trim() == "device.model=Agent Model,device.os.version=1.0");
    ensure!(owner.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;

    pg(&format!(
        "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) SELECT tenant_id,gen_random_uuid(),registration,source,epoch,scope,g,NULL,NULL,NULL,NULL,started_at-g,attempts,result,reason,batch,digest,sealed_at-g,false FROM mdm_access.collection_runs CROSS JOIN generate_series(1,230) g WHERE tenant_id='{TENANT}' AND id='{report_id}'"
    ))?;
    let partial_id = uuid::Uuid::new_v4();
    let failed_id = uuid::Uuid::new_v4();
    for body in [
        json!({"wireVersion":1,"reportId":partial_id,"sequence":1,"observedAt":2,"body":{"kind":"partial","values":[{"field":"device.model","value":{"kind":"known","value":"Unconfirmed"}}]}}),
        json!({"wireVersion":1,"reportId":failed_id,"sequence":2,"observedAt":3,"body":{"kind":"failed","code":"collectionFailed"}}),
    ] {
        ensure!(
            agent_call(
                router,
                Method::POST,
                "/api/agent/v1/reports",
                Some(credential),
                Some(body)
            )
            .await?
            .0 == StatusCode::ACCEPTED
        );
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND registration='{}' AND source='agent.builtin' AND NOT delivery_pending", registration["registrationId"].as_str().unwrap()))?.trim().parse::<i64>()? <= 224, "delivered Agent retention was not enforced");
    pg(&format!(
        "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) SELECT tenant_id,gen_random_uuid(),registration,source,epoch,scope,1000+g,NULL,NULL,NULL,NULL,started_at,attempts,result,reason,batch,digest,sealed_at,true FROM mdm_access.collection_runs CROSS JOIN generate_series(1,29) g WHERE tenant_id='{TENANT}' AND id='{partial_id}'"
    ))?;
    let mut capacity = tokio::task::JoinSet::new();
    for sequence in [3, 4] {
        let router = router.clone();
        let body = json!({"wireVersion":1,"reportId":uuid::Uuid::new_v4(),"sequence":sequence,"observedAt":4,"body":{"kind":"failed","code":"temporarilyUnavailable"}});
        capacity.spawn(async move {
            agent_call(
                &router,
                Method::POST,
                "/api/agent/v1/reports",
                Some(credential),
                Some(body),
            )
            .await
        });
    }
    let mut capacity_statuses = Vec::new();
    while let Some(result) = capacity.join_next().await {
        capacity_statuses.push(result??);
    }
    ensure!(
        capacity_statuses
            .iter()
            .filter(|result| result.0 == StatusCode::ACCEPTED)
            .count()
            == 1
    );
    ensure!(
        capacity_statuses
            .iter()
            .filter(|result| result.0 == StatusCode::SERVICE_UNAVAILABLE
                && result.1["code"] == "service_unavailable")
            .count()
            == 1,
        "concurrent capacity boundary was not linearized: {capacity_statuses:?}"
    );
    pg(&format!(
        "DELETE FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND registration='{}' AND source='agent.builtin' AND sequence>=1000",
        registration["registrationId"].as_str().unwrap()
    ))?;
    let runtime = agent_runtime(config).await?;
    let owner = crate::inventory_runtime::tests::start(runtime.clone()).await?;
    wait_agent_status(
        router,
        credential,
        partial_id,
        "needSnapshotPartial",
        "notApplicable",
    )
    .await?;
    wait_agent_status(
        router,
        credential,
        failed_id,
        "needSnapshotCollectionFailed",
        "notApplicable",
    )
    .await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{TENANT}' AND batch_id IN ('{partial_id}','{failed_id}')"))?.trim() == "0");
    ensure!(owner.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;
    ensure!(!pg(&format!("SELECT locator FROM mdm_access.credentials WHERE tenant_id='{TENANT}' AND registration='{}'", registration["registrationId"].as_str().unwrap()))?.contains(credential), "raw Agent credential persisted");
    let next_password = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    let next_credential = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
    browser.operation = Some(uuid::Uuid::new_v4());
    let (status, next_enrollment) = browser
        .call(
            router,
            Method::POST,
            "/api/v2/enrollments",
            Some(json!({"deviceId":"device-1","password":next_password,"channel":"agent"})),
        )
        .await?;
    ensure!(status == StatusCode::OK);
    let next_operation = uuid::Uuid::new_v4();
    let next_registration = json!({"wireVersion":1,"operationId":next_operation,"enrollmentId":next_enrollment["enrollmentId"],"password":next_password,"credential":next_credential,"capabilities":["inventory.basic.v1"]});
    access.fail_next(1);
    let rolled_back = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/registrations",
        None,
        Some(next_registration.clone()),
    )
    .await?;
    ensure!(
        rolled_back.0 == StatusCode::SERVICE_UNAVAILABLE
            && rolled_back.1["code"] == "service_unavailable"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.operations WHERE tenant_id='{TENANT}' AND operation_id='{next_operation}'"))?.trim() == "0", "rolled-back registration persisted");
    access.fail_next(2);
    let unknown = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/registrations",
        None,
        Some(next_registration.clone()),
    )
    .await?;
    ensure!(
        unknown.0 == StatusCode::SERVICE_UNAVAILABLE && unknown.1["code"] == "operation_unknown"
    );
    let recovered = agent_call(
        router,
        Method::POST,
        "/api/agent/v1/registrations",
        None,
        Some(next_registration),
    )
    .await?;
    ensure!(recovered.0 == StatusCode::OK);
    let stored_receipt: Value = serde_json::from_str(&pg(&format!(
        "SELECT result FROM mdm_access.operations WHERE tenant_id='{TENANT}' AND operation_id='{next_operation}'"
    ))?)?;
    ensure!(
        recovered.1 == stored_receipt,
        "registration ACK-loss retry did not recover the committed receipt"
    );
    ensure!(agent_call(router, Method::POST, "/api/agent/v1/reports", Some(credential), Some(json!({"wireVersion":1,"reportId":uuid::Uuid::new_v4(),"sequence":2,"observedAt":2,"body":{"kind":"failed","code":"collectionFailed"}}))).await?.0 == StatusCode::UNAUTHORIZED);
    ensure!(
        agent_call(
            router,
            Method::GET,
            &format!("/api/agent/v1/reports/{report_id}"),
            Some(credential),
            None
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    for (fault, expected) in [(1, "service_unavailable"), (2, "operation_unknown")] {
        let fault_report = uuid::Uuid::new_v4();
        let body = json!({"wireVersion":1,"reportId":fault_report,"sequence":100+fault,"observedAt":100+fault,"body":{"kind":"failed","code":"temporarilyUnavailable"}});
        access.fail_next(fault);
        let failed = agent_call(
            router,
            Method::POST,
            "/api/agent/v1/reports",
            Some(next_credential),
            Some(body.clone()),
        )
        .await?;
        ensure!(failed.0 == StatusCode::SERVICE_UNAVAILABLE && failed.1["code"] == expected);
        let persisted = pg(&format!(
            "SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{fault_report}'"
        ))?;
        ensure!(persisted.trim() == if fault == 1 { "0" } else { "1" });
        let retry = agent_call(
            router,
            Method::POST,
            "/api/agent/v1/reports",
            Some(next_credential),
            Some(body.clone()),
        )
        .await?;
        ensure!(retry.0 == StatusCode::ACCEPTED && retry.1["reportId"] == fault_report.to_string());
        ensure!(
            agent_call(
                router,
                Method::POST,
                "/api/agent/v1/reports",
                Some(next_credential),
                Some(body)
            )
            .await?
                == retry
        );
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{fault_report}'"))?.trim() == "1", "report recovery duplicated durable intake");
    }
    Ok(())
}

async fn revoke_http_matrix(
    config: &Value,
    reader: Arc<InventoryReader>,
    session: &Browser,
) -> Result<()> {
    let (grant, request, registration, credential, epoch) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage())?;
    pg(&format!("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','revoke-fixture','{INSTANCE}','revoke-device','enrollment','consumed',clock_timestamp()+interval '200 seconds');
        INSERT INTO mdm_access.requests(tenant_id,id,grant_id,channel) VALUES('{TENANT}','{request}','{grant}','mdm');
        INSERT INTO mdm_access.devices VALUES('{TENANT}','revoke-device');
        INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','revoke-device','mdm',1,'{request}','active');
        INSERT INTO mdm_access.credentials VALUES('{TENANT}','{credential}','{registration}','mdm',repeat('c',64),'active');
        INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','mdm.windows','{epoch}','{coverage}',true);"))?;
    let path = format!("/api/v2/devices/revoke-device/registrations/{registration}/revoke");
    let listing = "/api/v2/devices/revoke-device/registrations";
    let cfg = config.clone();
    let initial = app(&cfg, reader.clone()).await?;
    set_device_grants(
        &mut session.clone(),
        &initial,
        "revoke-device",
        &["inventory_read"],
    )
    .await?;
    let denied = app(&cfg, reader.clone()).await?;
    let mut browser = session.clone();
    ensure!(browser.call(&denied, Method::GET, listing, None).await?.0 == StatusCode::FORBIDDEN);
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        browser
            .call(&denied, Method::POST, &path, Some(json!({})))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    set_device_grants(&mut browser, &denied, "revoke-device", &["credentials"]).await?;
    let allowed = app(&cfg, reader).await?;
    browser = session.clone();
    let listed = browser.call(&allowed, Method::GET, listing, None).await?;
    ensure!(
        listed.0 == StatusCode::OK
            && listed.1["items"][0]["registrationId"] == registration.to_string()
    );
    ensure!(listed.1["items"][0]["status"] == "active" && listed.1["nextCursor"].is_null());
    ensure!(!listed.1.to_string().contains("password") && !listed.1.to_string().contains("secret"));
    ensure!(
        browser
            .call(
                &allowed,
                Method::GET,
                "/api/v2/devices/outside/registrations",
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        browser
            .call(
                &allowed,
                Method::GET,
                &format!("{listing}?after={registration}"),
                None
            )
            .await?
            .1["items"]
            == json!([])
    );
    ensure!(
        browser
            .call(
                &allowed,
                Method::GET,
                &format!("{listing}?after=invalid"),
                None
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    for bad in [
        "/api/v2/enrollments/not-a-uuid/resume",
        "/api/v2/enrollments/not-a-uuid/cancel",
        "/api/v2/devices/revoke-device/registrations/not-a-uuid/revoke",
    ] {
        let response = browser
            .call(&allowed, Method::POST, bad, Some(json!({})))
            .await?;
        ensure!(response.0 == StatusCode::BAD_REQUEST && response.1["code"] == "malformed_request");
    }
    for body in [None, Some(json!(null)), Some(json!({"unexpected":true}))] {
        let response = browser.call(&allowed, Method::POST, &path, body).await?;
        ensure!(response.0 == StatusCode::BAD_REQUEST && response.1["code"] == "malformed_request");
    }
    let cookie = browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let malformed = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("cookie", cookie)
        .header("x-csrf-token", browser.csrf.as_ref().unwrap())
        .header("idempotency-key", browser.operation.unwrap().to_string())
        .header("content-type", "application/json")
        .body(Body::from("{"))?;
    let response = allowed.clone().oneshot(malformed).await?;
    ensure!(response.status() == StatusCode::BAD_REQUEST);
    let csrf_saved = browser.csrf.take();
    ensure!(
        browser
            .call(&allowed, Method::POST, &path, Some(json!({})))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    browser.csrf = csrf_saved;
    let first = browser
        .call(&allowed, Method::POST, &path, Some(json!({})))
        .await?;
    ensure!(first.0 == StatusCode::OK, "revoke must use online Identity");
    ensure!(
        browser
            .call(&allowed, Method::POST, &path, Some(json!({})))
            .await?
            == first
    );
    ensure!(
        browser.call(&allowed, Method::GET, listing, None).await?.1["items"][0]["status"]
            == "revoked"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.registrations r JOIN mdm_access.credentials c ON c.tenant_id=r.tenant_id AND c.registration=r.id JOIN mdm_access.report_sources s ON s.tenant_id=r.tenant_id AND s.registration=r.id WHERE r.tenant_id='{TENANT}' AND r.id='{registration}' AND r.state='revoked' AND c.state='revoked' AND NOT s.enabled"
        ))?.trim() == "1"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.audit WHERE tenant_id='{TENANT}' AND operation_id='{}' AND action='credential_revoke' AND result='success'",
            browser.operation.unwrap()
        ))?.trim() == "1"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2-identity: only MDM-owned TLS PostgreSQL; no central service"]
async fn local_identity_mdm_authorization_and_revocation() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: Config = serde_json::from_value(base.clone())?;
    let reader = Arc::new(
        InventoryReader::connect(
            config
                .access_database
                .options()?
                .username("mdm_api")
                .password("api-fixture"),
        )
        .await?,
    );
    let initial = app(&base, reader.clone()).await?;
    let mut browser = Browser::default();
    ensure!(browser.login(&initial, "other").await? == StatusCode::OK);
    let credential = &browser.cookies["__Host-identity-session"];
    for (method, path) in [
        (Method::GET, "/api/v1/authorization".to_owned()),
        (Method::GET, format!("/api/v2/tenants/{TENANT}/session")),
        (Method::POST, "/api/v2/enrollments".to_owned()),
    ] {
        for cookie in [
            format!("__Host-identity-session={credential}; broken"),
            format!("__Host-identity-session={credential}; __Host-identity-session={credential}"),
        ] {
            let request = Request::builder()
                .method(method.clone())
                .uri(&path)
                .header("host", "mdm.example.test")
                .header("origin", "https://mdm.example.test")
                .header("x-identity-request", "1")
                .header("x-csrf-token", browser.csrf.as_ref().unwrap())
                .header("cookie", cookie)
                .body(Body::empty())?;
            let response = initial.clone().oneshot(request).await?;
            ensure!(
                response.status() == StatusCode::BAD_REQUEST,
                "strict host cookie boundary: {method} {path} returned {}",
                response.status()
            );
            ensure!(!response.headers().contains_key("set-cookie"));
        }
    }
    let (_, me) = browser
        .call(&initial, Method::GET, "/api/v1/authorization", None)
        .await?;
    ensure!(me["instanceId"] == INSTANCE && me["tenantId"] == TENANT && me["grants"] == json!([]));
    let subject = me["principalId"].as_str().unwrap();
    host_context_matrix(&base, reader.clone(), &browser, subject).await?;
    let query = "/api/v2/devices/device-1/inventory".to_owned();
    ensure!(browser.call(&initial, Method::GET, &query, None).await?.0 == StatusCode::FORBIDDEN);
    let allowed = base.clone();
    crate::identity_fixture::set_grants(
        TENANT,
        subject,
        crate::identity_fixture::device_grants(
            Some("device-1"),
            &["inventory_read", "device_wipe", "enrollment"],
        )?,
    )
    .await?;
    let agent_access = access_store(&allowed).await?;
    let authorized = app_with_access(&allowed, agent_access.clone()).await?;
    // Restarting the host preserves only the component credential, whose PG state is checked again.
    ensure!(
        browser
            .call(&authorized, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::OK
    );
    agent_matrix(&authorized, &allowed, &agent_access, &mut browser).await?;
    let scope = serde_json::to_string(
        &json!({"tenant":TENANT,"object":"99999999-9999-4999-8999-999999999991","registration":"99999999-9999-4999-8999-999999999991","source":"mdm.windows","dataset":"inventory","epoch":"99999999-9999-4999-8999-999999999992"}),
    )?;
    // Use the public Scope encoder, not JSON map key order, for the persisted identity.
    let scope: rss_observation::Scope = serde_json::from_str(&scope)?;
    let encoded = scope.encode()?.replace('\'', "''");
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage())?;
    let projection = rss_mdm_inventory_postgres::projection_scope(scope.tenant());
    let journal = projection.source().source();
    let generation = projection.generation();
    // Read-path fixture only. Device registration/credential proof is exercised by device PG T2.
    pg(&format!(
        r#"
        INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','99999999-9999-4999-8999-999999999993','read-fixture','{INSTANCE}','device-1','enrollment','consumed',clock_timestamp()+interval '200 seconds');
        INSERT INTO mdm_access.requests(tenant_id,id,grant_id,channel) VALUES('{TENANT}','99999999-9999-4999-8999-999999999994','99999999-9999-4999-8999-999999999993','mdm');
        INSERT INTO mdm_access.devices VALUES('{TENANT}','device-1') ON CONFLICT DO NOTHING;
        INSERT INTO mdm_access.registrations VALUES('{TENANT}','99999999-9999-4999-8999-999999999991','device-1','mdm',1,'99999999-9999-4999-8999-999999999994','active');
        INSERT INTO mdm_access.credentials VALUES('{TENANT}','99999999-9999-4999-8999-999999999995','99999999-9999-4999-8999-999999999991','mdm',repeat('a',64),'active');
        INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','99999999-9999-4999-8999-999999999991','mdm.windows','99999999-9999-4999-8999-999999999992','{coverage}',true);
        INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch) VALUES('{TENANT}','{journal}','{generation}','{encoded}','{coverage}','device.model','Model-A','fixture',1,2,'known','99999999-9999-4999-8999-999999999991','mdm.windows','99999999-9999-4999-8999-999999999992');
    "#
    ))?;

    let (status, assets) = browser.call(&authorized, Method::GET, &query, None).await?;
    ensure!(
        status == StatusCode::OK
            && assets["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"]
                == "Model-A"
    );
    ensure!(assets["tenantId"] == TENANT && assets["asset"]["device"]["device"] == "device-1");
    let outside = "/api/v2/devices/outside/inventory";
    ensure!(
        browser
            .call(&authorized, Method::GET, outside, None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Box::pin(management::matrix(&allowed, reader.clone(), &browser)).await?;
    enrollment_matrix(&authorized, &allowed, reader.clone(), &mut browser, &query).await?;
    native_accounts(&initial, &authorized, &mut browser, subject).await?;
    reader.close().await;
    println!("MDM_LOCAL_AUTHORITY_MATRIX_PASSED");
    Ok(())
}
async fn native_accounts(
    admin_router: &Router,
    product: &Router,
    browser: &mut Browser,
    principal: &str,
) -> Result<()> {
    let tenant = format!("/api/v2/tenants/{TENANT}");
    let mut admin = Browser::default();
    ensure!(admin.login(admin_router, "admin").await? == StatusCode::OK);
    let account = format!("{tenant}/accounts/{principal}");
    ensure!(
        browser
            .call(product, Method::GET, &format!("{tenant}/accounts"), None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        admin
            .call(
                admin_router,
                Method::POST,
                &format!("{tenant}/accounts/{ADMIN}/enabled"),
                Some(json!({"enabled":false}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    // Passive product queries do not extend idle; the current cookie survives a process restart.
    let before = pg(&format!(
        "SELECT jsonb_agg(idle_expires_at ORDER BY session_id)::text FROM identity_authority.sessions WHERE tenant_id='{TENANT}' AND principal_id='{principal}'"
    ))?;
    for _ in 0..2 {
        ensure!(
            browser
                .call(product, Method::GET, "/api/v1/authorization", None)
                .await?
                .0
                == StatusCode::OK
        );
    }
    ensure!(
        before
            == pg(&format!(
                "SELECT jsonb_agg(idle_expires_at ORDER BY session_id)::text FROM identity_authority.sessions WHERE tenant_id='{TENANT}' AND principal_id='{principal}'"
            ))?
    );
    // Successful authentication cannot be reused while the authority becomes unavailable.
    pg("REVOKE SELECT ON identity_authority.sessions FROM mdm_identity_runtime")?;
    let denied = browser
        .call(product, Method::GET, "/api/v1/authorization", None)
        .await?;
    pg("GRANT SELECT ON identity_authority.sessions TO mdm_identity_runtime")?;
    ensure!(denied.0 == StatusCode::SERVICE_UNAVAILABLE && denied.1.get("roles").is_none());
    let identity = crate::identity_fixture::identity(TENANT).await?;
    let credentials = crate::enrollment_credentials::Credentials::new(monotonic(), 16);
    let cache = |browser: &Browser| -> Result<uuid::Uuid> {
        Ok(
            credentials.insert(rss_identity_core::session::SessionSecret::parse(
                browser.cookies["__Host-identity-session"].clone(),
            )?)?,
        )
    };
    for state in ["membership", "enabled"] {
        let reference = cache(browser)?;
        ensure!(
            admin
                .call(
                    admin_router,
                    Method::POST,
                    &format!("{account}/{state}"),
                    Some(json!({"enabled":false}))
                )
                .await?
                .0
                == StatusCode::OK
        );
        ensure!(
            browser
                .call(product, Method::GET, "/api/v1/authorization", None)
                .await?
                .0
                == StatusCode::UNAUTHORIZED
        );
        ensure!(
            admin
                .call(
                    admin_router,
                    Method::POST,
                    &format!("{account}/{state}"),
                    Some(json!({"enabled":true}))
                )
                .await?
                .0
                == StatusCode::OK
        );
        ensure!(
            identity
                .authenticate(credentials.get(reference)?)
                .await
                .is_err()
        );
        *browser = Browser::default();
        ensure!(browser.login(product, "other").await? == StatusCode::OK);
    }
    let reference = cache(browser)?;
    let mut stale = browser.clone();
    ensure!(
        browser
            .call(
                product,
                Method::POST,
                &format!("{tenant}/session/refresh"),
                None
            )
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        identity
            .authenticate(credentials.get(reference)?)
            .await
            .is_err()
    );
    let logout_reference = cache(browser)?;
    ensure!(
        stale
            .call(product, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        browser
            .call(
                product,
                Method::POST,
                &format!("{tenant}/session/logout"),
                None
            )
            .await?
            .0
            == StatusCode::NO_CONTENT
    );
    ensure!(
        browser
            .call(product, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        identity
            .authenticate(credentials.get(logout_reference)?)
            .await
            .is_err()
    );
    *browser = Browser::default();
    ensure!(browser.login(product, "other").await? == StatusCode::OK);
    let password_reference = cache(browser)?;
    ensure!(
        admin
            .call(
                admin_router,
                Method::POST,
                &format!("{account}/password"),
                Some(json!({"password":"Changed-fixture-password-2026!"}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        browser
            .call(product, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        identity
            .authenticate(credentials.get(password_reference)?)
            .await
            .is_err()
    );
    ensure!(
        admin
            .call(
                admin_router,
                Method::POST,
                &format!("{account}/password"),
                Some(json!({"password":PASSWORD}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    // The component owns its atomic security event; a second product audit cannot
    // overwrite a committed account mutation or discard the native response.
    pg("REVOKE INSERT ON mdm_access.audit FROM mdm_access,mdm_management_runtime")?;
    let created = admin
        .call(
            admin_router,
            Method::POST,
            &format!("{tenant}/accounts"),
            Some(json!({"login":"managed-user","password":PASSWORD})),
        )
        .await;
    pg("GRANT INSERT ON mdm_access.audit TO mdm_access,mdm_management_runtime")?;
    let created = created?;
    ensure!(created.0 == StatusCode::CREATED && created.1["principalId"].is_string());
    let mut managed = Browser::default();
    ensure!(managed.login(admin_router, "managed-user").await? == StatusCode::OK);
    ensure!(managed.call(admin_router, Method::POST, &format!("{tenant}/account/password"), Some(json!({"currentPassword":PASSWORD,"password":"Self-changed-fixture-password-2026!"}))).await?.0 == StatusCode::OK);
    let wrong_tenant = "/api/v2/tenants/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/session";
    ensure!(
        admin
            .call(admin_router, Method::GET, wrong_tenant, None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    // Product management policy asks the component for Recent(300s), including native accounts.
    pg(&format!(
        "UPDATE identity_authority.sessions SET auth_time=auth_time-301,absolute_expires_at=absolute_expires_at-301 WHERE tenant_id='{TENANT}' AND principal_id='{ADMIN}'"
    ))?;
    let stale_management = admin
        .call(
            admin_router,
            Method::POST,
            &format!("{tenant}/accounts"),
            Some(json!({"login":"stale-must-not-create","password":PASSWORD})),
        )
        .await;
    let passive = admin
        .call(
            admin_router,
            Method::GET,
            &format!("{tenant}/accounts"),
            None,
        )
        .await;
    pg(&format!(
        "UPDATE identity_authority.sessions SET auth_time=auth_time+301,absolute_expires_at=absolute_expires_at+301 WHERE tenant_id='{TENANT}' AND principal_id='{ADMIN}'"
    ))?;
    let stale_management = stale_management?;
    ensure!(
        stale_management.0 == StatusCode::FORBIDDEN
            && stale_management.1["code"] == "reauthentication_required"
    );
    ensure!(passive?.0 == StatusCode::OK);
    ensure!(pg("SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='stale-must-not-create'")?.trim() == "0");
    let container = std::env::var("MDM_TEST_PG_CONTAINER")?;
    let reference = cache(&admin)?;
    command(&["pause", &container], None)?;
    let (http, enrollment) = tokio::join!(
        admin.call(admin_router, Method::GET, "/api/v1/authorization", None),
        identity.authenticate(credentials.get(reference)?)
    );
    command(&["unpause", &container], None)?;
    let http = http?;
    ensure!(
        http.0 == StatusCode::SERVICE_UNAVAILABLE
            && http.1.get("roles").is_none()
            && enrollment.is_err()
    );
    Ok(())
}

async fn host_context_matrix(
    base: &Value,
    reader: Arc<InventoryReader>,
    browser: &Browser,
    subject: &str,
) -> Result<()> {
    let path = format!("/api/identity-host/v1/tenants/{TENANT}/context");
    for permissions in [
        json!([]),
        json!(["accounts"]),
        json!(["providers"]),
        json!(["accounts", "providers"]),
    ] {
        let mut config = base.clone();
        config["identity_management"] = if permissions.as_array().unwrap().is_empty() {
            json!([])
        } else {
            json!([{"tenant_id":TENANT,"instance_id":INSTANCE,"principal_id":subject,"permissions":permissions}])
        };
        let router = app(&config, reader.clone()).await?;
        ensure!(
            Browser::default()
                .call(&router, Method::GET, &path, None)
                .await?
                .0
                == StatusCode::UNAUTHORIZED
        );
        let mut member = browser.clone();
        let before = member
            .call(
                &router,
                Method::GET,
                &format!("/api/v2/tenants/{TENANT}/session"),
                None,
            )
            .await?
            .1;
        let (status, context) = member.call(&router, Method::GET, &path, None).await?;
        ensure!(status == StatusCode::OK);
        ensure!(
            context
                == json!({"tenantId":TENANT,"principalId":subject,"sessionId":before["session"]["id"],"navigation":{
            "manageAccounts":permissions.as_array().unwrap().contains(&json!("accounts")),
            "manageProviders":permissions.as_array().unwrap().contains(&json!("providers"))}})
        );
        let after = member
            .call(
                &router,
                Method::GET,
                &format!("/api/v2/tenants/{TENANT}/session"),
                None,
            )
            .await?
            .1;
        ensure!(before["session"]["idleExpiresAt"] == after["session"]["idleExpiresAt"]);
        let wrong = path.replace(TENANT, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        ensure!(
            member.call(&router, Method::GET, &wrong, None).await?.0 == StatusCode::UNAUTHORIZED
        );
    }
    let router = app(base, reader).await?;
    let (_, context) = browser
        .clone()
        .call(&router, Method::GET, &path, None)
        .await?;
    ensure!(context["navigation"] == json!({"manageAccounts":false,"manageProviders":false}));
    Ok(())
}

async fn browser_subject(browser: &Browser, router: &Router) -> Result<String> {
    let (status, value) = browser
        .clone()
        .call(router, Method::GET, "/api/v1/authorization", None)
        .await?;
    ensure!(status == StatusCode::OK);
    Ok(value["principalId"].as_str().unwrap().into())
}
async fn set_device_grants(
    browser: &mut Browser,
    router: &Router,
    device: &str,
    operations: &[&str],
) -> Result<()> {
    let subject = browser_subject(browser, router).await?;
    crate::identity_fixture::set_grants(
        TENANT,
        &subject,
        crate::identity_fixture::device_grants(Some(device), operations)?,
    )
    .await
}
async fn set_management_grants(subject: &str, permissions: Value) -> Result<()> {
    let mut grants = permissions
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            Ok(crate::authorization::Grant {
                operation: serde_json::from_value(p.clone())?,
                scope: crate::authorization::Scope::Tenant,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    grants.extend(crate::identity_fixture::device_grants(
        None,
        &["inventory_read"],
    )?);
    crate::identity_fixture::set_grants(TENANT, subject, grants).await
}
