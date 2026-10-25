//! Windows native TOU continuation. The browser receives only presentation and CSRF data.
//! ref: axum axum/src/form.rs; Microsoft Windows Azure AD integration with MDM.
use super::*;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use rss_mdm_http_contract::Router;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
const COOKIE: &str = "__Host-rss-entra-flow";
const ENTRY: &str = "/enrollment/windows/entra/terms";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    redirect_uri: String,
    #[serde(rename = "client-request-id")]
    client_request_id: Uuid,
    #[serde(rename = "api-version")]
    api_version: String,
    mode: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Flow {
    token: Zeroizing<String>,
    csrf: Zeroizing<String>,
    opaque: Zeroizing<String>,
    callback: String,
    origin: String,
    client_request_id: Uuid,
    join: bool,
    revision: i64,
    version: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Finish {
    csrf_token: String,
    accepted: bool,
}
struct Stored {
    id: Uuid,
    digest: String,
    expires_at: i64,
    accepted: Option<bool>,
    flow: Flow,
}
pub fn browser_routes(app: Arc<HttpState>, envelope: crate::boundary::Envelope) -> Router {
    crate::boundary::wrap(
        Router::new()
            .route(
                "/api/v1/windows/entra/terms",
                rss_mdm_http_contract::routing::get(start).owned(
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/api/v1/windows/entra/terms/context",
                rss_mdm_http_contract::routing::get(context).owned(
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/api/v1/windows/entra/terms/finish",
                rss_mdm_http_contract::routing::post(finish).owned(
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .with_state(app)
            .layer(axum::extract::DefaultBodyLimit::max(4096)),
        envelope,
    )
}
fn aad(tenant: TenantId, id: Uuid) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    crate::protection::native_aad(tenant, "windows.entra.web-flow", &id)
}
fn redirect(location: &str) -> Result<Response, Error> {
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).map_err(|_| Error::Malformed)?,
    );
    Ok(response)
}
fn origin(headers: &HeaderMap) -> Result<String, Error> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Malformed)?;
    Ok(format!("https://{host}"))
}
fn cookie(headers: &HeaderMap) -> Result<(Uuid, String), Error> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|part| part.trim().strip_prefix(&format!("{COOKIE}=")));
    let value = values.next().ok_or(Error::Unauthorized)?;
    if values.next().is_some() || value.len() > 128 {
        return Err(Error::Unauthorized);
    }
    let (id, secret) = value.split_once('.').ok_or(Error::Unauthorized)?;
    if secret.is_empty() {
        return Err(Error::Unauthorized);
    }
    Ok((
        Uuid::parse_str(id).map_err(|_| Error::Unauthorized)?,
        hash(secret),
    ))
}
async fn load(
    c: &mut PgConnection,
    app: &HttpState,
    entra: &Entra,
    id: Uuid,
    digest: &str,
    lock: bool,
) -> Result<Stored, Error> {
    let query = if lock {
        "SELECT sealed,extract(epoch FROM expires_at)::bigint AS expiry,accepted FROM mdm_windows.entra_web_flows WHERE tenant_id=$1::uuid AND id=$2 AND cookie_digest=$3 AND expires_at>clock_timestamp() FOR UPDATE"
    } else {
        "SELECT sealed,extract(epoch FROM expires_at)::bigint AS expiry,accepted FROM mdm_windows.entra_web_flows WHERE tenant_id=$1::uuid AND id=$2 AND cookie_digest=$3 AND expires_at>clock_timestamp()"
    };
    let row = sqlx::query(query)
        .bind(entra.tenant.to_string())
        .bind(id)
        .bind(digest)
        .fetch_optional(c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    let sealed: Vec<u8> = row.try_get("sealed").map_err(db)?;
    let plain = app
        .protection
        .open_bytes(&sealed, &aad(entra.tenant, id)?)
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    let flow = serde_json::from_slice(plain.expose())
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    Ok(Stored {
        id,
        digest: digest.into(),
        expires_at: row.try_get("expiry").map_err(db)?,
        accepted: row.try_get("accepted").map_err(db)?,
        flow,
    })
}
fn policy_matches(
    settings: &Settings,
    flow: &Flow,
    subject: &VerifiedExternalSubject,
) -> Result<(), Error> {
    settings
        .policy
        .permits(subject.claims().map_err(|_| Error::Unauthorized)?.user)?;
    if settings.revision != flow.revision || settings.policy.terms_version != flow.version {
        return Err(Error::Conflict);
    }
    subject.check_live().map_err(|_| Error::Unauthorized)
}
async fn start(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::Extension(a): axum::Extension<RequestAudit>,
    Query(input): Query<Start>,
) -> Result<Response, Error> {
    // Never redirect to an untrusted URI, even when token validation fails.
    if !owner(&app)?
        .config
        .native_callbacks
        .contains(&input.redirect_uri)
    {
        return Err(Error::Malformed);
    }
    let callback = input.redirect_uri.clone();
    match start_flow(State(app), headers, axum::Extension(a), Query(input)).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let code = match &error {
                Error::Malformed => "invalid_request",
                Error::Unauthorized | Error::Forbidden => "unauthorized_client",
                _ => "server_error",
            };
            let mut response =
                redirect(&format!("{callback}?error={code}&error_description={code}"))?;
            response.extensions_mut().insert(error);
            Ok(response)
        }
    }
}
async fn start_flow(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::Extension(a): axum::Extension<RequestAudit>,
    Query(input): Query<Start>,
) -> Result<Response, Error> {
    let entra = owner(&app)?;
    if input.client_request_id.is_nil()
        || input.api_version != "1.0"
        || input
            .mode
            .as_deref()
            .is_some_and(|mode| mode != "azureadjoin")
        || !entra.config.native_callbacks.contains(&input.redirect_uri)
    {
        return Err(Error::Malformed);
    }
    let token = bearer(&headers)?;
    let subject = entra.verify(token.clone()).await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let expires_at = subject
        .claims()
        .map_err(|_| Error::Unauthorized)?
        .expires_at
        .min(now + 300);
    if expires_at <= now {
        return Err(Error::Unauthorized);
    }
    let id = Uuid::new_v4();
    let secret = Zeroizing::new(crate::enrollment::random());
    let digest = hash(&secret);
    let settings = {
        let mut tx = app.access.begin_read(&entra.tenant.to_string()).await?;
        settings_in(&mut tx, &entra.tenant.to_string(), false).await?
    };
    let stored = Stored {
        id,
        digest,
        expires_at,
        accepted: None,
        flow: Flow {
            token,
            csrf: Zeroizing::new(crate::enrollment::random()),
            opaque: Zeroizing::new(crate::enrollment::random()),
            callback: input.redirect_uri,
            origin: origin(&headers)?,
            client_request_id: input.client_request_id,
            join: input.mode.is_some(),
            revision: settings.revision,
            version: settings.policy.terms_version,
        },
    };
    commit(&app, &subject, &stored, None, &a).await?;
    let mut response = redirect(ENTRY)?;
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}={id}.{}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age={}",
            secret.as_str(),
            expires_at - now
        ))
        .map_err(|_| Error::Malformed)?,
    );
    Ok(response)
}
async fn context(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Error> {
    let entra = owner(&app)?;
    let (id, digest) = cookie(&headers)?;
    let mut tx = app.access.begin_read(&entra.tenant.to_string()).await?;
    let stored = load(&mut tx, &app, entra, id, &digest, false).await?;
    if origin(&headers)? != stored.flow.origin {
        return Err(Error::Forbidden);
    }
    let subject = entra.verify(stored.flow.token.clone()).await?;
    let settings = settings_in(&mut tx, &entra.tenant.to_string(), false).await?;
    policy_matches(&settings, &stored.flow, &subject)?;
    Ok(Json(
        serde_json::json!({"termsText":settings.policy.terms_text,"termsVersion":stored.flow.version,"mode":if stored.flow.join {Some("azureadjoin")}else{None},"canDecline":!stored.flow.join,"csrfToken":stored.flow.csrf.as_str(),"expiresAt":stored.expires_at}),
    ))
}
async fn finish(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::Extension(a): axum::Extension<RequestAudit>,
    Form(input): Form<Finish>,
) -> Result<Response, Error> {
    let entra = owner(&app)?;
    let (id, digest) = cookie(&headers)?;
    let stored = {
        let mut tx = app.access.begin_read(&entra.tenant.to_string()).await?;
        load(&mut tx, &app, entra, id, &digest, false).await?
    };
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
            != Some(stored.flow.origin.as_str())
        || origin(&headers)? != stored.flow.origin
        || !crate::enrollment::equal(&input.csrf_token, &stored.flow.csrf)
    {
        return Err(Error::Forbidden);
    }
    if stored.flow.join && !input.accepted {
        return Err(Error::Forbidden);
    }
    let subject = entra.verify(stored.flow.token.clone()).await?;
    commit(&app, &subject, &stored, Some(input.accepted), &a).await?;
    let mut location = format!(
        "{}?IsAccepted={}",
        stored.flow.callback,
        if input.accepted { "true" } else { "false" }
    );
    if input.accepted {
        location.push_str("&OpaqueBlob=");
        location.push_str(&stored.flow.opaque);
    }
    location.push_str("&client-request-id=");
    location.push_str(&stored.flow.client_request_id.to_string());
    redirect(&location)
}

/// One audit transaction binds both initial persistence and replayable decisions.
async fn commit(
    app: &HttpState,
    subject: &VerifiedExternalSubject,
    stored: &Stored,
    decision: Option<bool>,
    a: &RequestAudit,
) -> Result<(), Error> {
    let entra = owner(app)?;
    let action = if decision.is_some() {
        "windows_entra_consent"
    } else {
        "windows_entra_terms_start"
    };
    a.identify_service("service:windows-entra-terms");
    a.operation(
        stored.id,
        action,
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
    let result = app
        .audit_store
        .write(
            entra.tenant,
            &budget.source_control(),
            (app, entra, subject, stored, decision, a),
            |(app, entra, subject, stored, decision, a), tx| {
                Box::pin(async move {
                    let (app, entra, subject, stored, decision, a) =
                        (*app, *entra, *subject, *stored, *decision, *a);
                    let replayed = tx
                        .with_connection_context(
                            &mut (app, entra, subject, stored, decision),
                            |(app, entra, subject, stored, decision), c| {
                                Box::pin(async move {
                                    let (app, entra, subject, stored, decision) =
                                        (*app, *entra, *subject, *stored, *decision);
                                    let settings =
                                        settings_in(c, &entra.tenant.to_string(), true).await?;
                                    policy_matches(&settings, &stored.flow, subject)?;
                                    let replayed = if let Some(accepted) = decision {
                                        decide(c, app, entra, subject, stored, accepted).await?
                                    } else {
                                        persist(c, app, entra, stored).await?;
                                        false
                                    };
                                    subject.check_live().map_err(|_| Error::Unauthorized)?;
                                    Ok::<_, Error>(replayed)
                                })
                            },
                        )
                        .await?;
                    let action = if decision.is_some() {
                        "windows_entra_consent"
                    } else {
                        "windows_entra_terms_start"
                    };
                    let fact = Fact::business(
                        a,
                        &format!("{action}:{}", stored.id),
                        302,
                        "success",
                        None,
                    )?;
                    (if replayed {
                        Ok(())
                    } else {
                        app.audit_store.append(tx, &fact).await
                    })?;
                    a.mark_commit_started();
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(result, a)
}
async fn persist(
    c: &mut PgConnection,
    app: &HttpState,
    entra: &Entra,
    stored: &Stored,
) -> Result<(), Error> {
    let plain = Zeroizing::new(serde_json::to_vec(&stored.flow).map_err(|_| Error::Malformed)?);
    let sealed = app
        .protection
        .seal_bytes(&plain, &aad(entra.tenant, stored.id)?)
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    sqlx::query("DELETE FROM mdm_windows.entra_web_flows WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() AND id IN(SELECT id FROM mdm_windows.entra_web_flows WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() ORDER BY expires_at LIMIT 128)")
        .bind(entra.tenant.to_string()).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_windows.entra_web_flows(tenant_id,id,cookie_digest,sealed,expires_at) VALUES($1::uuid,$2,$3,$4,to_timestamp($5))")
        .bind(entra.tenant.to_string()).bind(stored.id).bind(&stored.digest).bind(sealed).bind(stored.expires_at as f64).execute(c).await.map_err(db)?;
    Ok(())
}
async fn decide(
    c: &mut PgConnection,
    app: &HttpState,
    entra: &Entra,
    subject: &VerifiedExternalSubject,
    stored: &Stored,
    accepted: bool,
) -> Result<bool, Error> {
    let current = load(c, app, entra, stored.id, &stored.digest, true).await?;
    if let Some(previous) = current.accepted {
        return if previous == accepted {
            Ok(true)
        } else {
            Err(Error::Conflict)
        };
    }
    if accepted {
        sqlx::query("DELETE FROM mdm_windows.entra_consents WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() AND digest IN(SELECT digest FROM mdm_windows.entra_consents WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() ORDER BY expires_at LIMIT 128)")
            .bind(entra.tenant.to_string()).execute(&mut *c).await.map_err(db)?;
        let claims = subject.claims().map_err(|_| Error::Unauthorized)?;
        sqlx::query("INSERT INTO mdm_windows.entra_consents(tenant_id,digest,entra_tenant,entra_user,revision,expires_at) VALUES($1::uuid,$2,$3,$4,$5,to_timestamp($6))")
            .bind(entra.tenant.to_string()).bind(hash(&current.flow.opaque)).bind(claims.tenant).bind(claims.user).bind(current.flow.revision).bind(current.expires_at as f64).execute(&mut *c).await.map_err(db)?;
    }
    sqlx::query(
        "UPDATE mdm_windows.entra_web_flows SET accepted=$3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(entra.tenant.to_string())
    .bind(stored.id)
    .bind(accepted)
    .execute(c)
    .await
    .map_err(db)?;
    Ok(false)
}
