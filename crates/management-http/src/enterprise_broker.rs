//! Controlled native Broker ingress and authenticated RP backend handoff.
use crate::{Error, identity::failure};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use rss_mdm_agent_wire::{enterprise as wire, runtime::Secret};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{
    Operation, Router, catalog,
    routing::{get, post},
};
use rss_mdm_registration_service::{agent::Service, enterprise::broker::Client};
use std::sync::Arc;
use uuid::Uuid;
struct Services {
    registration: Arc<Service>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    identity: Arc<crate::identity::Identity>,
    origin: String,
    platform_configuration: serde_json::Value,
}
pub fn routes(
    registration: Option<Arc<Service>>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    identity: Arc<crate::identity::Identity>,
    host: &str,
    platform_configuration: serde_json::Value,
) -> Router {
    let Some(registration) = registration else {
        return Router::new();
    };
    Router::new()
        .route(
            "/api/v1/device-access/broker/browser",
            post(initialize).owned(&catalog::DEVICE_ACCESS, &[Operation::Action]),
        )
        .route(
            "/api/v1/device-access/broker",
            post(begin).owned(&catalog::DEVICE_ACCESS, &[Operation::Action]),
        )
        .route(
            "/api/v1/device-access/broker/complete",
            post(complete).owned(&catalog::DEVICE_ACCESS, &[Operation::Action]),
        )
        .route(
            "/api/v1/device-access/broker/{id}",
            get(status).owned(&catalog::DEVICE_ACCESS, &[Operation::Get]),
        )
        .route(
            "/api/v1/device-access/broker/{id}/cancel",
            post(cancel).owned(&catalog::DEVICE_ACCESS, &[Operation::Action]),
        )
        .route(
            "/api/v1/device-access/relying-parties/{rp}/consume",
            post(consume).owned(&catalog::DEVICE_ACCESS, &[Operation::Action]),
        )
        .route(
            "/api/v1/device-access/relying-parties/{rp}/sessions/{id}",
            get(current).owned(&catalog::DEVICE_ACCESS, &[Operation::Get]),
        )
        .with_state(Arc::new(Services {
            registration,
            execution,
            identity,
            origin: format!("https://{host}"),
            platform_configuration,
        }))
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(10),
    )
}
fn browser(
    s: &Services,
    h: &HeaderMap,
    create: bool,
    require_origin: bool,
) -> Result<Secret, Error> {
    let origins = h.get_all("origin").iter().count();
    if (require_origin && origins != 1)
        || origins > 1
        || (origins == 1
            && h.get("origin").and_then(|v| v.to_str().ok()) != Some(s.origin.as_str()))
        || h.get("sec-fetch-site").is_some_and(|v| v != "same-origin")
        || h.contains_key("authorization")
        || h.contains_key("x-api-key")
    {
        return Err(Error::Forbidden);
    }
    let mut values = Vec::new();
    for header in h.get_all("cookie").iter() {
        for pair in header.to_str().map_err(|_| Error::Malformed)?.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name == "__Host-rss-broker"
            {
                values.push(value);
            }
        }
    }
    match values.as_slice() {
        [value] => Secret::parse(value).map_err(|_| Error::Malformed),
        [] if create => {
            use base64::Engine;
            let mut bytes = [0u8; 32];
            bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            Secret::parse(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
                .map_err(|_| Error::Malformed)
        }
        _ => Err(Error::Unauthorized),
    }
}
fn client<'a>(s: &'a Services, rp: &str) -> Result<&'a dyn Client, Error> {
    s.identity
        .enterprise_clients
        .get(rp)
        .map(|c| c.as_ref())
        .ok_or(Error::Forbidden)
}
fn backend<'a>(s: &'a Services, rp: &str, h: &HeaderMap) -> Result<&'a dyn Client, Error> {
    if h.get_all("authorization").iter().count() != 1 || h.contains_key("cookie") {
        return Err(Error::Unauthorized);
    }
    let credential = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?;
    let c = client(s, rp)?;
    if !c.authenticate(credential) {
        return Err(Error::Unauthorized);
    }
    Ok(c)
}
async fn begin(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    h: HeaderMap,
    Json(input): Json<wire::Begin>,
) -> Result<Response, Error> {
    let browser = browser(&s, &h, false, true)?;
    let client = client(&s, &input.relying_party)?;
    let (context, created) = s
        .registration
        .broker_prepare(&input, &browser, client, s.execution.as_ref(), &a)
        .await?;
    let challenge = if created {
        let challenge = s
            .identity
            .authority
            .begin_platform_login(
                s.identity.tenant,
                input.binding_id,
                rss_identity_postgres::platform::PlatformPurpose::EnterpriseRp(input.relying_party),
                browser.expose().to_owned(),
                rss_identity_postgres::AttemptSource::parse("mdm-enterprise-broker")
                    .map_err(failure)?,
                deadline(),
            )
            .await
            .map_err(failure)?;
        s.registration
            .broker_attach_challenge(
                input.operation_id,
                &browser,
                challenge,
                s.execution.as_ref(),
                &a,
            )
            .await?
    } else if context.phase == wire::Phase::AwaitingProof {
        context.challenge.ok_or(Error::Conflict)?
    } else {
        return Err(Error::Conflict);
    };
    let mut response = Json(challenge).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "__Host-rss-broker={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600",
            browser.expose()
        ))
        .map_err(|_| Error::Malformed)?,
    );
    Ok(response)
}
async fn complete(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    h: HeaderMap,
    Json(input): Json<wire::Complete>,
) -> Result<Json<wire::Status>, Error> {
    let browser = browser(&s, &h, false, true)?;
    let context = s
        .registration
        .broker_claim(&input, &browser, s.execution.as_ref(), &a)
        .await?;
    let attempt = context.attempt.ok_or(Error::Conflict)?;
    let result = async {
        let client = client(&s, &context.relying_party.id)?;
        if client.fingerprint() != context.relying_party.target_fingerprint {
            return Err(Error::Forbidden);
        }
        let evidence = zeroize::Zeroizing::new(
            serde_json::to_vec(&input.proof).map_err(|_| Error::Malformed)?,
        );
        let login = s
            .identity
            .authority
            .complete_platform_login(
                s.identity.tenant,
                input.challenge_id,
                input.nonce,
                browser.expose().to_owned(),
                evidence.to_vec(),
                deadline(),
            )
            .await
            .map_err(failure)?;
        let assertion = login.assertion.ok_or(Error::Forbidden)?;
        if assertion.target != *client.target() {
            return Err(Error::Forbidden);
        }
        let session = rss_identity_core::session::SessionSecret::parse(
            login.session.secret().expose().to_owned(),
        )
        .map_err(|_| Error::Unauthorized)?;
        let actor = s
            .identity
            .authority
            .inspect_session(s.identity.tenant, session, deadline())
            .await
            .map_err(failure)?;
        let token = client
            .exchange(
                assertion.expose(),
                assertion.expires_at,
                &context.subject.subject,
            )
            .await?;
        s.registration
            .broker_finish(
                input.operation_id,
                attempt,
                &browser,
                &actor,
                token,
                s.execution.as_ref(),
                &a,
            )
            .await
            .map_err(Error::from)
    }
    .await;
    match result {
        Ok(status) => Ok(Json(status)),
        Err(error) => {
            // Once claimed, a lost response can follow committed Identity/IdP work. Never replay it.
            s.registration
                .broker_fail(input.operation_id, attempt, &browser, true, &a)
                .await?;
            Err(error)
        }
    }
}
async fn status(
    State(s): State<Arc<Services>>,
    Path(id): Path<Uuid>,
    h: HeaderMap,
) -> Result<Json<wire::Status>, Error> {
    let browser = browser(&s, &h, false, false)?;
    Ok(Json(
        s.registration
            .broker_status(id, &browser, s.execution.as_ref())
            .await?,
    ))
}
async fn cancel(
    State(s): State<Arc<Services>>,
    Path(id): Path<Uuid>,
    Extension(a): Extension<RequestAudit>,
    h: HeaderMap,
) -> Result<Json<serde_json::Value>, Error> {
    let browser = browser(&s, &h, false, true)?;
    s.registration.broker_cancel(id, &browser, &a).await?;
    Ok(Json(serde_json::json!({"cancelled":true})))
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Consume {
    session: Uuid,
    operation_id: Uuid,
    continuation: Secret,
}
async fn consume(
    State(s): State<Arc<Services>>,
    Path(rp): Path<String>,
    Extension(a): Extension<RequestAudit>,
    h: HeaderMap,
    Json(input): Json<Consume>,
) -> Result<Json<rss_mdm_registration_service::enterprise::broker::Consumed>, Error> {
    let client = backend(&s, &rp, &h)?;
    let reference = s
        .registration
        .broker_reference(
            client,
            input.session,
            Some(&input.continuation),
            s.execution.as_ref(),
        )
        .await?;
    let facts = s
        .identity
        .authority
        .recheck_session_reference(s.identity.tenant, &reference, deadline())
        .await
        .map_err(failure)?;
    s.registration
        .broker_consume(
            client,
            input.session,
            input.operation_id,
            &input.continuation,
            &facts,
            s.execution.as_ref(),
            &a,
        )
        .await?;
    Ok(Json(
        s.registration
            .broker_release(
                &s.identity.authority,
                client,
                input.session,
                input.operation_id,
                &input.continuation,
                s.platform_configuration.clone(),
            )
            .await?,
    ))
}

async fn current(
    State(s): State<Arc<Services>>,
    Path((rp, id)): Path<(String, Uuid)>,
    h: HeaderMap,
) -> Result<Json<serde_json::Value>, Error> {
    let client = backend(&s, &rp, &h)?;
    let principal = s
        .registration
        .broker_current(
            &s.identity.authority,
            client,
            id,
            s.platform_configuration.clone(),
        )
        .await?;
    Ok(Json(
        serde_json::json!({"active":true,"session":id,"principal":principal}),
    ))
}

async fn initialize(State(s): State<Arc<Services>>, h: HeaderMap) -> Result<Response, Error> {
    let browser = browser(&s, &h, true, true)?;
    let mut response = Json(serde_json::json!({"ready":true})).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "__Host-rss-broker={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600",
            browser.expose()
        ))
        .map_err(|_| Error::Malformed)?,
    );
    Ok(response)
}
