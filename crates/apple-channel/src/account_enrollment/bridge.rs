use super::*;
use crate::database::db;
use axum::{
    Extension, Form,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use rss_mdm_audit_integration::RequestAudit;
use serde::Deserialize;
const COOKIE: &str = "__Host-rss-apple-flow";
#[derive(schemars::JsonSchema, Deserialize)]
pub struct Start {
    #[serde(rename = "user-identifier")]
    user_identifier: String,
}
fn cookie(headers: &HeaderMap) -> Result<(Uuid, String), Error> {
    if headers.get_all(header::COOKIE).iter().count() != 1 {
        return Err(Error::Unauthorized);
    }
    let input = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthorized)?;
    let values = input
        .split(';')
        .filter_map(|s| s.trim().split_once('='))
        .filter(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(Error::Unauthorized);
    }
    let (id, secret) = values[0].split_once('.').ok_or(Error::Unauthorized)?;
    let id = Uuid::parse_str(id).map_err(|_| Error::Unauthorized)?;
    if secret.len() != 43
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(Error::Unauthorized);
    }
    Ok((id, secret.to_owned()))
}
fn check_cookie(
    row: &sqlx::postgres::PgRow,
    tenant: &str,
    id: Uuid,
    secret: &str,
) -> Result<(), Error> {
    if row
        .try_get::<Option<String>, _>("cookie_hash")
        .map_err(db)?
        .as_deref()
        != Some(cookie_hash(tenant, id, secret).as_str())
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub(super) async fn start(
    State(app): State<Arc<HttpState>>,
    Path(id): Path<Uuid>,
    Query(input): Query<Start>,
    StartHeaders(headers): StartHeaders,
    Extension(audit): Extension<RequestAudit>,
) -> Result<BridgePage, Error> {
    let name = account_name(&input.user_identifier)?;
    let tenant = app.identity.tenant().to_string();
    let secret = rss_mdm_registration_service::enrollment::random();
    audit.identify_service("service:apple-account-browser");
    let previous = cookie(&headers).ok();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &budget.source_control(),
            (&app, &tenant, id, &name, &secret, &previous, &audit),
            |(app, tenant, id, name, secret, previous, audit), tx| {
                Box::pin(async move {
                    let replayed = tx
                        .with_connection_context(
                            &mut (*tenant, *id, *name, *secret, *previous),
                            |(tenant, id, name, secret, previous), c| {
                                Box::pin(select_account_on(
                                    c,
                                    Selection {
                                        tenant,
                                        id: *id,
                                        name,
                                        secret,
                                        previous,
                                    },
                                ))
                            },
                        )
                        .await?;

                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-account-browser:{id}"),
                        200,
                        "success",
                        Some(*id),
                    )
                    .map_err(Error::from)?;
                    (if replayed {
                        Ok(())
                    } else {
                        app.audit_store.append(tx, &fact).await
                    })
                    .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        )
                    }
                    audit.mark_commit_started();
                    Ok(replayed)
                })
            },
        )
        .await;
    let replayed = crate::operations::settle(outcome, &audit)?;
    let mut response = page(&app, &name)?;
    if !replayed {
        response.cookie = Some(
            HeaderValue::from_str(&format!(
                "{COOKIE}={id}.{secret}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"
            ))
            .map_err(|_| Error::Malformed)?,
        );
    }
    Ok(response)
}
pub(super) async fn resume(
    State(app): State<Arc<HttpState>>,
    ResumeHeaders(headers): ResumeHeaders,
) -> Result<BridgePage, Error> {
    let (id, secret) = cookie(&headers)?;
    let tenant = app.identity.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let row = store::flow(&mut tx, &tenant, id).await?;
    check_cookie(&row, &tenant, id, &secret)?;
    let name: String = row.try_get("account").map_err(db)?;
    let binding = store::bound_account(
        &mut tx,
        &tenant,
        row.try_get("organization").map_err(db)?,
        &name,
    )
    .await?;
    if row.try_get::<i64, _>("binding_revision").map_err(db)?
        != binding.try_get::<i64, _>("revision").map_err(db)?
    {
        return Err(Error::Unauthorized);
    }
    page(&app, &name)
}
fn page(app: &HttpState, name: &str) -> Result<BridgePage, Error> {
    let name = name
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    let tenant = app.identity.tenant().to_string();
    let html = format!(
        "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>注册工作设备</title><body data-tenant=\"{tenant}\"><h1>注册工作设备</h1><p>组织账户：{name}</p><p>请使用与该组织账户关联的 RSS 账户登录。</p><form id=\"login\"><label>RSS 登录名 <input name=\"login\" autocomplete=\"username\" required></label><label>密码 <input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label><button>登录</button></form><div id=\"providers\"></div><form id=\"finish\" method=\"post\" action=\"/api/v1/apple/account-enrollment/finish\" hidden><input name=\"csrf\" type=\"hidden\"><button>继续注册</button></form><p id=\"message\" role=\"status\"></p><script src=\"/api/v1/apple/account-enrollment/bridge.js\" defer></script></body></html>"
    );
    Ok(BridgePage { html, cookie: None })
}
pub(super) async fn script() -> BridgeScript {
    BridgeScript
}

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    csrf: String,
}
pub(super) async fn finish(
    State(app): State<Arc<HttpState>>,
    FinishHeaders(mut headers): FinishHeaders,
    Extension(audit): Extension<RequestAudit>,
    Form(input): Form<Finish>,
) -> Result<BridgeRedirect, Error> {
    let (id, secret) = cookie(&headers)?;
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
            != Some(app.authentication.origin.as_str())
        || headers.contains_key("x-identity-request")
        || headers.contains_key("x-csrf-token")
    {
        return Err(Error::Forbidden);
    }
    // The HTML form carries the same credential-bound CSRF proof; verification remains with Identity.
    headers.insert(
        "x-csrf-token",
        HeaderValue::from_str(&input.csrf).map_err(|_| Error::Forbidden)?,
    );
    headers.insert("x-identity-request", HeaderValue::from_static("1"));
    let proof = authenticate(&app, &headers, true).await?;
    proof.bind_audit(&audit)?;
    audit.operation(
        id,
        "apple_account_authorize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let tenant = proof.tenant_id().to_owned();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &budget.source_control(),
            (&app, &proof, &tenant, id, &secret, &audit),
            |(app, proof, tenant, id, secret, audit), tx| {
                Box::pin(async move {
                    let (token, replayed, enrollment) = tx
                        .with_connection_context(
                            &mut (*app, *proof, *tenant, *id, *secret, *audit),
                            |(app, proof, tenant, id, secret, audit), c| {
                                Box::pin(authorize_on(
                                    c,
                                    Authorization {
                                        app,
                                        proof,
                                        tenant,
                                        id: *id,
                                        secret,
                                        audit,
                                    },
                                ))
                            },
                        )
                        .await?;

                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-account-authorize:{id}"),
                        308,
                        "success",
                        Some(enrollment),
                    )
                    .map_err(Error::from)?;
                    (if replayed {
                        Ok(())
                    } else {
                        app.audit_store.append(tx, &fact).await
                    })
                    .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        )
                    }
                    audit.mark_commit_started();
                    Ok(token)
                })
            },
        )
        .await;
    let token = crate::operations::settle(outcome, &audit)?;
    Ok(BridgeRedirect(
        HeaderValue::from_str(&format!(
            "apple-remotemanagement-user-login://authentication-results?access-token={token}"
        ))
        .map_err(|_| Error::Malformed)?,
    ))
}

struct Selection<'a> {
    tenant: &'a String,
    id: Uuid,
    name: &'a String,
    secret: &'a String,
    previous: &'a Option<(Uuid, String)>,
}
async fn select_account_on(
    c: &mut sqlx::PgConnection,
    input: Selection<'_>,
) -> Result<bool, Error> {
    let Selection {
        tenant,
        id,
        name,
        secret,
        previous,
    } = input;
    let row = store::flow(c, tenant, id).await?;
    if row.try_get::<String, _>("domain").map_err(db)?
        != name.rsplit_once('@').ok_or(Error::Malformed)?.1
        || row
            .try_get::<Option<String>, _>("expected_account")
            .map_err(db)?
            .is_some_and(|v| v != name.as_str())
    {
        return Err(Error::Unauthorized);
    }
    let binding =
        store::bound_account(c, tenant, row.try_get("organization").map_err(db)?, name).await?;
    if let Some(existing) = row.try_get::<Option<String>, _>("account").map_err(db)? {
        if existing != name.as_str()
            || row.try_get::<i64, _>("binding_revision").map_err(db)?
                != binding.try_get::<i64, _>("revision").map_err(db)?
        {
            return Err(Error::Unauthorized);
        }
        let (old_id, old_secret) = previous.as_ref().ok_or(Error::Unauthorized)?;
        if *old_id != id {
            return Err(Error::Unauthorized);
        }
        check_cookie(&row, tenant, id, old_secret)?;
        return Ok::<_, Error>(true);
    }
    sqlx::query("UPDATE mdm_apple.account_flows SET account=$3,binding_revision=$4,cookie_hash=$5 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).bind(name).bind(binding.try_get::<i64,_>("revision").map_err(db)?).bind(cookie_hash(tenant,id,secret)).execute(c).await.map_err(db)?;
    Ok(false)
}

struct Authorization<'a> {
    app: &'a HttpState,
    proof: &'a AuthorizedPrincipal,
    tenant: &'a String,
    id: Uuid,
    secret: &'a String,
    audit: &'a RequestAudit,
}
async fn authorize_on(
    c: &mut sqlx::PgConnection,
    input: Authorization<'_>,
) -> Result<(String, bool, Uuid), Error> {
    let Authorization {
        app,
        proof,
        tenant,
        id,
        secret,
        audit,
    } = input;
    let target: Uuid = sqlx::query_scalar(
        "SELECT target_enrollment FROM mdm_apple.account_flows WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .ok_or(Error::Unauthorized)?;
    rss_mdm_registration_service::enrollment::native::lock_account_issuance(c, proof, target)
        .await?;
    let row = store::flow(c, tenant, id).await?;
    check_cookie(&row, tenant, id, secret)?;
    let name: String = row.try_get("account").map_err(db)?;
    let org: Uuid = row.try_get("organization").map_err(db)?;
    let binding = store::bound_account(c, tenant, org, &name).await?;
    if binding
        .try_get::<Uuid, _>("principal")
        .map_err(db)?
        .to_string()
        != proof.principal_id()
        || binding
            .try_get::<Uuid, _>("instance")
            .map_err(db)?
            .to_string()
            != proof.instance_id()
        || binding.try_get::<i64, _>("revision").map_err(db)?
            != row.try_get::<i64, _>("binding_revision").map_err(db)?
    {
        return Err(Error::Unauthorized);
    }
    let enrollment: Uuid = row.try_get("target_enrollment").map_err(db)?;
    let old = row.try_get::<Option<Vec<u8>>, _>("material").map_err(db)?;
    let material = if let Some(sealed) = old {
        let current: i64 = sqlx::query_scalar(
            "SELECT account_version FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(tenant)
        .bind(enrollment)
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
        if current != row.try_get::<i64, _>("authorization_version").map_err(db)? {
            return Err(Error::Unauthorized);
        }
        let plain = app
            .protection
            .open_bytes(&sealed, &aad(tenant, id, "apple.account.material")?)
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
        serde_json::from_slice::<Material>(plain.expose())
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?
    } else {
        Material {
            token: rss_mdm_registration_service::enrollment::random().into(),
            challenge: rss_mdm_registration_service::enrollment::random().into(),
        }
    };
    let (_receipt, replayed) = rss_mdm_registration_service::enrollment::native::issue_in(
        c,
        proof,
        app.account_authority.as_ref(),
        enrollment,
        id,
        &material.challenge,
        audit,
    )
    .await?;
    let version: i64 = sqlx::query_scalar(
        "SELECT account_version FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(enrollment)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    let sealed = app
        .protection
        .seal_bytes(
            &zeroize::Zeroizing::new(serde_json::to_vec(&material).map_err(|_| Error::Malformed)?),
            &aad(tenant, id, "apple.account.material")?,
        )
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    sqlx::query("UPDATE mdm_apple.account_flows SET revoked=true,material=NULL,profile=NULL,token_hash=NULL WHERE tenant_id=$1::uuid AND enrollment=$2 AND id<>$3 AND NOT revoked").bind(tenant).bind(enrollment).bind(id).execute(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.account_flows SET enrollment=$3,authorization_version=$4,token_hash=$5,material=$6 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(enrollment).bind(version).bind(token_hash(tenant,&material.token)).bind(sealed).execute(c).await.map_err(db)?;
    proof.check_live()?;
    Ok::<_, Error>((material.token.to_string(), replayed, enrollment))
}

pub(super) struct StartHeaders(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for StartHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for StartHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = rss_mdm_http_contract::signature::Request::default();
        request.headers.insert(
            "cookie".into(),
            rss_mdm_http_contract::signature::Schema::request::<String>(),
        );
        request.required_headers = vec![];
        request
    }
}

pub(super) struct ResumeHeaders(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ResumeHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for ResumeHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = rss_mdm_http_contract::signature::Request::default();
        request.headers.insert(
            "cookie".into(),
            rss_mdm_http_contract::signature::Schema::request::<String>(),
        );
        request.required_headers = vec!["cookie"];
        request
    }
}

pub(super) struct FinishHeaders(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for FinishHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for FinishHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = rss_mdm_http_contract::signature::Request::default();
        for name in ["cookie", "origin"] {
            request.headers.insert(
                name.into(),
                rss_mdm_http_contract::signature::Schema::request::<String>(),
            );
        }
        request.required_headers = vec!["cookie", "origin"];
        request.headers.insert(
            "x-identity-request".into(),
            rss_mdm_http_contract::signature::Schema {
                direction: rss_mdm_http_contract::signature::Direction::Request,
                value: serde_json::Value::Bool(false),
            },
        );
        request.headers.insert(
            "x-csrf-token".into(),
            rss_mdm_http_contract::signature::Schema {
                direction: rss_mdm_http_contract::signature::Direction::Request,
                value: serde_json::Value::Bool(false),
            },
        );
        request
    }
}

const CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self' apple-remotemanagement-user-login:; frame-ancestors 'none'; base-uri 'none'";
pub(super) struct BridgePage {
    html: String,
    cookie: Option<HeaderValue>,
}
impl IntoResponse for BridgePage {
    fn into_response(self) -> Response {
        let mut response = Html(self.html).into_response();
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
        if let Some(cookie) = self.cookie {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
        response
    }
}
impl rss_mdm_http_contract::signature::Output for BridgePage {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{Representation, Response, Schema};
        let mut response = Response::empty(200);
        response.body = Some(Representation {
            content_type: "text/html; charset=utf-8",
            schema: Schema::response::<String>(),
        });
        let mut csp = Schema::response::<String>();
        csp.value["const"] = CSP.into();
        response
            .headers
            .insert("content-security-policy".into(), csp);
        response
            .headers
            .insert("set-cookie".into(), Schema::response::<String>());
        vec![response]
    }
}
pub(super) struct BridgeScript;
impl BridgeScript {
    const MEDIA: &'static str = "application/javascript; charset=utf-8";
}
impl IntoResponse for BridgeScript {
    fn into_response(self) -> Response {
        ([("content-type", Self::MEDIA)], include_str!("bridge.js")).into_response()
    }
}
impl rss_mdm_http_contract::signature::Output for BridgeScript {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{Representation, Response, Schema};
        let mut response = Response::empty(200);
        response.body = Some(Representation {
            content_type: Self::MEDIA,
            schema: Schema::response::<String>(),
        });
        vec![response]
    }
}
pub(super) struct BridgeRedirect(HeaderValue);
impl IntoResponse for BridgeRedirect {
    fn into_response(self) -> Response {
        let mut response = StatusCode::PERMANENT_REDIRECT.into_response();
        response.headers_mut().insert(header::LOCATION, self.0);
        response
    }
}
impl rss_mdm_http_contract::signature::Output for BridgeRedirect {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        let mut response = rss_mdm_http_contract::signature::Response::empty(308);
        response.headers.insert(
            "location".into(),
            rss_mdm_http_contract::signature::Schema::response::<String>(),
        );
        vec![response]
    }
}
