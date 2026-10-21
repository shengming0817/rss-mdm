use super::{process::*, runtime::*, *};
use uuid::Uuid;
pub(crate) fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}
pub(crate) async fn ok(
    browser: &mut Browser,
    router: &Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let query = method == Method::POST && path == "/api/v1/device-queries";
    let saved = method == Method::POST && path.ends_with("/execute");
    let body = if query || saved {
        Some(request(
            if saved { 1 } else { 0 },
            body.unwrap_or_else(|| json!({})),
        ))
    } else {
        body
    };
    let (s, v) = browser.call(router, method, path, body).await?;
    ensure!(
        s == StatusCode::OK || s == StatusCode::ACCEPTED,
        "asset request {path}: {s} {v}"
    );
    if query || saved {
        ensure!(s == StatusCode::ACCEPTED, "query must be asynchronous");
        let status = v["asset"]["statusUrl"].as_str().unwrap();
        await_task(browser, router, status).await?;
        let (s, page) = browser
            .call(router, Method::GET, &format!("{status}/items"), None)
            .await?;
        ensure!(s == StatusCode::OK, "query result: {s} {page}");
        return Ok(page);
    }
    if let Some(task) = v["task"].as_str() {
        let status = if let Some(url) = v["statusUrl"].as_str() {
            url.to_owned()
        } else {
            format!("{path}/tasks/{task}")
        };
        await_task(browser, router, &status).await?;
    }
    Ok(v)
}

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
        if method == Method::GET && path.contains("/collections/") {
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
            let secret = identity::credential_for(case_tenant(), login)?;
            self.cookies
                .insert("__Host-identity-session".into(), secret.expose().into());
            self.csrf = Some(secret.csrf());
            return Ok(self
                .call(
                    app,
                    Method::GET,
                    &format!("/api/v1/identity/tenants/{}/session", case_tenant()),
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
                &format!(
                    "/api/v1/identity/tenants/{TENANT}/login",
                    TENANT = case_tenant()
                ),
                Some(json!({"login":case::login(login),"password":password})),
            )
            .await?
            .0)
    }
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
