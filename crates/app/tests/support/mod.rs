#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
#![allow(
    dead_code,
    reason = "capability fixtures have multiple independent test consumers"
)]
//! Shared setup only. Assertions remain with each capability's tests.
pub(crate) mod authority;
pub(crate) use crate::publication_support::pg::case;
pub(crate) mod identity;
pub(crate) use crate::config::Config;
pub(crate) use crate::publication_support;
pub(crate) use anyhow::{Result, ensure};
pub(crate) use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
pub(crate) use http_body_util::BodyExt;
pub(crate) use reqwest::Client;
pub(crate) use rss_mdm_inventory_postgres::InventoryReader;
pub(crate) use serde_json::{Value, json};
pub(crate) use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
pub(crate) use tower::ServiceExt;
pub(crate) fn case_tenant() -> &'static str {
    crate::test_support::case::tenant()
}
pub(crate) fn case_device() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| format!("/api/v1/devices/{}", case::name("device-1")))
}

pub(crate) use case::admin as case_admin;
pub(crate) use identity::{INSTANCE, PASSWORD};
#[derive(Default, Clone)]
pub(crate) struct Browser {
    pub(crate) network: Option<(Client, String)>,
    pub(crate) cookies: BTreeMap<String, String>,
    pub(crate) csrf: Option<String>,
    pub(crate) operation: Option<uuid::Uuid>,
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
    pub(crate) async fn call_headers(
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
    pub(crate) async fn login(&mut self, app: &Router, login: &str) -> Result<StatusCode> {
        if matches!(login, "admin" | "other") {
            let identity = identity::identity(case_tenant()).await?;
            let secret = identity::credential(&identity, login)?;
            self.cookies
                .insert("__Host-identity-session".into(), secret.expose().into());
            self.csrf = Some(secret.csrf());
            return Ok(self
                .call(
                    app,
                    Method::GET,
                    &format!("/api/v2/tenants/{}/session", case_tenant()),
                    None,
                )
                .await?
                .0);
        }
        self.login_password(app, login, identity::PASSWORD).await
    }
    pub(crate) async fn login_password(
        &mut self,
        app: &Router,
        login: &str,
        password: &str,
    ) -> Result<StatusCode> {
        Ok(self
            .call(
                app,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/login", TENANT = case_tenant()),
                Some(json!({"login":case::login(login),"password":password})),
            )
            .await?
            .0)
    }
}

pub(crate) fn command(args: &[&str], input: Option<&str>) -> Result<String> {
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

pub(crate) fn pg(sql: &str) -> Result<String> {
    pg_tenant(case_tenant(), sql)
}

pub(crate) fn audit_records() -> Result<Vec<crate::audit_test_support::Record>> {
    crate::audit_test_support::decode_hex(&pg(&format!(
        "SELECT encode(canonical,'hex') FROM rss_audit.records WHERE tenant_id='{TENANT}' ORDER BY position",
        TENANT = case_tenant()
    ))?)
}

pub(crate) fn audit_count(
    predicate: impl Fn(&crate::audit_test_support::Record) -> bool,
) -> Result<usize> {
    Ok(audit_records()?.iter().filter(|r| predicate(r)).count())
}

pub(crate) fn pg_tenant(tenant: &str, sql: &str) -> Result<String> {
    uuid::Uuid::parse_str(tenant)?;
    let config: Config =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
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
            &config.access_database.name,
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        Some(&format!(
            "BEGIN; SET LOCAL rss.tenant_id='{tenant}'; {sql}; COMMIT;"
        )),
    )
}

pub(crate) async fn database(value: &Value) -> Result<Arc<crate::Database>> {
    let config: Config = serde_json::from_value(value.clone())?;
    Ok(Arc::new(
        crate::Database::connect(config.access_database.options()?).await?,
    ))
}

pub(crate) async fn app(value: &Value, _reader: Arc<InventoryReader>) -> Result<Router> {
    Ok(app_with_access(value, database(value).await?).await?.0)
}

pub(crate) async fn app_with_access(
    value: &Value,
    access: Arc<crate::Database>,
) -> Result<(Router, Arc<rss_mdm_audit_integration::AuditStore>)> {
    let c: Config = serde_json::from_value(value.clone())?;
    let audit_store = access.audit_store(&c.audit).await?;
    let (router, _, _) = crate::api::application_fixture(
        c,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
        audit_store.clone(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("fixture application admission: {error:?}"))?;
    Ok((
        router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        ))),
        audit_store,
    ))
}

pub(crate) fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(|| {
        rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
    }))
}

pub(crate) async fn start_automation(value: &Value) -> Result<Option<rss_runtime::ShutdownStack>> {
    if !crate::test_support::case::owns_worker() {
        return Ok(None);
    }
    let config: Config = serde_json::from_value(value.clone())?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    let access = crate::Database::connect(config.access_database.options()?).await?;
    let audit_store = access.audit_store(&config.audit).await?;
    let service = config
        .flow
        .open(
            audit_store,
            rss_request_context::TenantId::parse(case_tenant())?,
            Arc::new(crate::clock::SystemClock),
            crate::flow::execution::open_content(&config)?,
            |resource| startup.stage_resource(rss_runtime::DynManagedResource::new_box(resource)),
        )
        .await?;
    let automation = crate::automation::Automation::connect(
        service.planning.clone(),
        service.assets.clone(),
        config.flow.storage.database.options()?,
    )
    .await?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.clone()),
    ));
    let notifications = crate::worker_wake::Listener::new(
        config.access_database.options()?,
        rss_request_context::TenantId::parse(case_tenant())?,
    );
    let signals = notifications.signals.clone();
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        notifications.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.registration().critical());
    launch.stage_deferred_task_with_token(automation.registration(signals.flow()).critical());
    launch.finish();
    Ok(Some(stack))
}

pub(crate) async fn await_task(
    browser: &mut Browser,
    router: &Router,
    path: &str,
) -> Result<Value> {
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
                "SELECT coalesce(jsonb_agg(p),'[]') FROM (SELECT j.id,j.kind,j.forwarded,j.failure,r.phase AS group_phase,r.object_count,s.phase AS scope_phase FROM mdm_automation.automation_jobs j LEFT JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(j.tenant_id,j.id) LEFT JOIN mdm_planning.scope_runs s ON (s.tenant_id,s.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{TENANT}' AND NOT j.completed ORDER BY j.id LIMIT 16)p",
                TENANT = case_tenant()
            ))?;
            anyhow::bail!("task {path} exceeded fixture deadline; last {last}; pending {progress}")
        }
    }
}

pub(crate) async fn agent_call(
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

pub(crate) async fn wait_agent_status(
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
                &format!("/api/agent/v4/reports/{report_id}"),
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

pub(crate) async fn agent_runtime(
    config: &Value,
) -> Result<Arc<crate::inventory_runtime::InventoryRuntime>> {
    let access = database(config).await?;
    let config: Config = serde_json::from_value(config.clone())?;
    Ok(crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access.inventory(),
        rss_request_context::TenantId::parse(case_tenant())?,
        monotonic(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?)
}

pub(crate) async fn browser_subject(browser: &Browser, router: &Router) -> Result<String> {
    let (status, value) = browser
        .clone()
        .call(router, Method::GET, "/api/v1/authorization", None)
        .await?;
    ensure!(status == StatusCode::OK);
    Ok(value["principalId"].as_str().unwrap().into())
}

pub(crate) async fn set_device_grants(
    browser: &mut Browser,
    router: &Router,
    device: &str,
    operations: &[&str],
) -> Result<()> {
    let subject = browser_subject(browser, router).await?;
    crate::test_support::identity::set_grants(
        case_tenant(),
        &subject,
        crate::test_support::identity::device_grants(Some(device), operations)?,
    )
    .await
}

pub(crate) async fn set_management_grants(subject: &str, permissions: Value) -> Result<()> {
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
    grants.extend(crate::test_support::identity::device_grants(
        None,
        &["inventory_read"],
    )?);
    crate::test_support::identity::set_grants(case_tenant(), subject, grants).await
}

pub(crate) mod http;
pub(crate) mod inventory;
pub(crate) use uuid::Uuid;

pub(crate) mod agent;

pub(crate) mod software;

pub(crate) mod process;

pub(crate) mod software_execution;

pub(crate) mod agent_execution;

pub(crate) mod planning_http;
pub(crate) mod publication_http;

pub(crate) fn credential(label: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret(label))
}

pub(crate) async fn stop_worker(owner: Option<rss_runtime::ShutdownStack>) -> Result<()> {
    if let Some(owner) = owner {
        ensure!(owner.shutdown().join().await?.is_clean());
    }
    Ok(())
}

pub(crate) fn secret(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(case::name(label).as_bytes()).into()
}

pub(crate) mod channel_onboarding;
