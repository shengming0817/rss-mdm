use crate::Error;
use axum::{
    Extension, Json,
    extract::{DefaultBodyLimit, Path, Query, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(v: Body<T>) -> Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}
pub(crate) fn routes() -> Router<Arc<TaskState>> {
    Router::new()
        .route(
            "/device-access",
            get(access_directory)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                )
                .windowed(&rss_mdm_registration_service::device_access::DISCOVERY),
        )
        .route(
            "/device-access/begin",
            post(access_begin).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/device-access/confirm",
            post(access_confirm).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/device-access/recovery-uses",
            post(access_recovery_use).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/task-trust/observations",
            post(observe_task_trust).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/task-trust",
            get(task_trust)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                )
                .post(acknowledge_task_trust)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
        )
        .route(
            "/tasks/claim",
            post(claim).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/tasks/{id}/enrollment",
            post(native_enrollment).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/current-user",
            get(current_user)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                )
                .put(login_user)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                )
                .delete(logout_user)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
        )
        .route(
            "/self-service",
            get(directory).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/self-service/invocations",
            post(invoke)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                )
                .layer(DefaultBodyLimit::max(131072)),
        )
        .route(
            "/self-service/invocations/{id}",
            get(invocation_status).owned(
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/tasks/{id}/events",
            post(event)
                .owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                )
                .layer(DefaultBodyLimit::max(wire::MAX_TASK_REQUEST_BYTES)),
        )
        .route(
            "/tasks/{id}/content",
            get(download).owned(
                &contracts::DOWNLOAD_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
}
async fn authenticate(
    app: &TaskState,
    headers: &HeaderMap,
    peer: Option<&rss_mdm_certificate::ClientCertificateEvidence>,
    audit: &RequestAudit,
) -> Result<crate::device::DevicePrincipal, crate::AgentError> {
    authenticate_for(app, headers, peer, audit, true).await
}
async fn authenticate_for(
    app: &TaskState,
    headers: &HeaderMap,
    peer: Option<&rss_mdm_certificate::ClientCertificateEvidence>,
    audit: &RequestAudit,
    task_required: bool,
) -> Result<crate::device::DevicePrincipal, crate::AgentError> {
    let principal = crate::authenticate(&app.enrollment, headers, peer).await?;
    let mut tx = app.access.begin(&principal.tenant().to_string()).await?;
    use rss_mdm_execution_service::channels::Agent;
    let binding = crate::Bindings
        .binding(
            &mut tx,
            principal.tenant().to_string(),
            principal.registration(),
        )
        .await
        .map_err(Error::from)?;
    tx.commit().await.map_err(crate::database::db)?;
    if !binding.is_some_and(|b| b.inventory() && (!task_required || b.task())) {
        return Err(task_error(Error::Forbidden));
    }
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    Ok(principal)
}
fn task_error(error: impl Into<Error>) -> crate::AgentError {
    match error.into() {
        Error::Forbidden => crate::AgentError::Wire(wire::ErrorCode::PermissionDenied),
        error if error.is_not_found() => crate::AgentError::Wire(wire::ErrorCode::TaskNotFound),
        other => other.into(),
    }
}
async fn claim(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::TaskClaimRequest>,
) -> Result<Json<Value>, crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let principal = authenticate(&app, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        audit.operation(
            input.operation_id(),
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        Ok(Json(
            app.execution
                .claim_action(&principal, &input, &audit)
                .await
                .map_err(task_error)?,
        ))
    })
    .await
}
async fn event(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Body<wire::TaskEventRequest>,
) -> Result<Json<Value>, crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let principal = authenticate(&app, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        audit.operation(
            input.operation_id(),
            "command_accept",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        Ok(Json(
            app.execution
                .action_event(&principal, id, &input, &audit)
                .await
                .map_err(task_error)?,
        ))
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Download {
    attempt: Uuid,
    artifact: Option<String>,
}
async fn download(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<Download>,
) -> Result<Response, crate::AgentError> {
    crate::bounded(async {
        let principal = authenticate(&app, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        audit.operation(
            id,
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let content = app
            .execution
            .action_content(
                &principal,
                id,
                query.attempt,
                query.artifact.as_deref(),
                &audit,
            )
            .await
            .map_err(task_error)?;
        crate::content::response(content, &headers)
            .await
            .map_err(task_error)
    })
    .await
}

use rss_mdm_audit_integration::RequestAudit;

pub struct TaskState {
    pub access: Arc<crate::Store>,
    pub enrollment: Arc<rss_mdm_registration_service::agent::Service>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub identity: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
}

pub(crate) fn installation_routes() -> Router<Arc<rss_mdm_execution_service::ExecutionService>> {
    Router::new().route(
        "/installations/{id}/package",
        get(installation_package).owned(
            &contracts::DOWNLOAD_AGENT_CHANNEL,
            &[RouteOperation::Action],
        ),
    )
}

async fn installation_package(
    State(execution): State<Arc<rss_mdm_execution_service::ExecutionService>>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, crate::AgentError> {
    let content = execution
        .installation_content(id, &audit)
        .await
        .map_err(task_error)?;
    crate::content::response(content, &headers)
        .await
        .map_err(task_error)
}

async fn employee(
    app: &TaskState,
    headers: &HeaderMap,
    audit: &RequestAudit,
) -> Result<Option<rss_mdm_authorization_service::context::AuthorizedPrincipal>, crate::AgentError>
{
    let credentials = headers
        .get_all("x-rss-user-session")
        .iter()
        .collect::<Vec<_>>();
    if credentials.is_empty() {
        return Ok(None);
    }
    if credentials.len() != 1 {
        return Err(Error::Unauthorized.into());
    }
    let secret = rss_identity_core::session::SessionSecret::parse(
        credentials[0]
            .to_str()
            .map_err(|_| Error::Unauthorized)?
            .into(),
    )
    .map_err(|_| Error::Unauthorized)?;
    let proof = app
        .identity
        .authenticate(
            &app.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Cookie(secret),
        )
        .await
        .map_err(Error::from)?;
    proof.bind_audit(audit).map_err(Error::from)?;
    Ok(Some(proof))
}
async fn directory(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Query(input): Query<wire::SelfServiceDirectory>,
) -> Result<Json<Value>, crate::AgentError> {
    crate::bounded(async {
        let p = authenticate(&app, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        let proof = employee(&app, &headers, &audit).await?;
        app.execution
            .self_service_directory(&p, proof.as_ref(), &input, &audit)
            .await
            .map(Json)
            .map_err(task_error)
    })
    .await
}
async fn invoke(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::SelfServiceInvoke>,
) -> Result<(axum::http::StatusCode, Json<Value>), crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let p = authenticate(&app, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        let proof = employee(&app, &headers, &audit).await?;
        let response = app
            .execution
            .invoke_self_service(&p, proof.as_ref(), &input, &audit)
            .await
            .map_err(task_error)?;
        Ok((axum::http::StatusCode::ACCEPTED, Json(response)))
    })
    .await
}
async fn invocation_status(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, crate::AgentError> {
    crate::bounded(async {
        let p = authenticate(&app, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        let proof = employee(&app, &headers, &audit).await?;
        app.execution
            .self_service_status(&p, proof.as_ref(), id, &audit)
            .await
            .map(Json)
            .map_err(task_error)
    })
    .await
}

async fn native_enrollment(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Body<rss_mdm_agent_wire::enroll::NativeEnrollmentRequest>,
) -> Result<Json<rss_mdm_agent_wire::enroll::NativeEnrollmentReceipt>, crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let principal = authenticate(&app, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        audit.operation(
            input.operation_id,
            "agent_native_enrollment",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        Ok(Json(
            app.execution
                .native_enrollment(&principal, id, &input, &audit)
                .await
                .map_err(task_error)?,
        ))
    })
    .await
}

async fn task_trust(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
) -> Result<Json<rss_mdm_agent_wire::task_trust::Trust>, crate::AgentError> {
    crate::bounded(async {
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|p| &p.0), &audit, false).await?;
        app.execution
            .agent_task_trust(&p, &audit)
            .await
            .map(Json)
            .map_err(task_error)
    })
    .await
}
async fn acknowledge_task_trust(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<rss_mdm_agent_wire::task_trust::Acknowledgement>,
) -> Result<Json<rss_mdm_agent_wire::task_trust::Acknowledgement>, crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|p| &p.0), &audit, false).await?;
        app.execution
            .acknowledge_task_trust(&p, &audit, &input)
            .await
            .map_err(task_error)?;
        Ok(Json(input))
    })
    .await
}

async fn observe_task_trust(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<rss_mdm_agent_wire::task_trust::Observation>,
) -> Result<Json<rss_mdm_agent_wire::task_trust::Observation>, crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|p| &p.0), &audit, false).await?;
        app.execution
            .observe_task_trust(&p, &audit, &input)
            .await
            .map_err(task_error)?;
        Ok(Json(input))
    })
    .await
}

async fn current_user(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
) -> Result<Json<wire::CurrentUser>, crate::AgentError> {
    crate::bounded(async {
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|p| &p.0), &audit, false).await?;
        app.enrollment
            .current_user(&p, &app.identity)
            .await
            .map(Json)
            .map_err(|e| Error::from(e).into())
    })
    .await
}
async fn login_user(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::CurrentUserChange>,
) -> Result<Json<wire::CurrentUser>, crate::AgentError> {
    let input = body(input)?;
    let (p, user) = crate::bounded(async {
        current_user_stage(&audit, "device_authentication");
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|p| &p.0), &audit, false).await?;
        current_user_stage(&audit, "employee_authentication");
        let user = employee(&app, &headers, &audit)
            .await?
            .ok_or(Error::Unauthorized)?;
        Ok((p, user))
    })
    .await?;
    // Preflight may expire; an entered source transaction owns its settlement budget.
    current_user_stage(&audit, "binding_write");
    let result = app
        .enrollment
        .change_current_user(&p, Some(&user), &input, &app.identity, &audit)
        .await;
    current_user_stage(&audit, "binding_finished");
    result.map(Json).map_err(|e| Error::from(e).into())
}
async fn logout_user(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::CurrentUserChange>,
) -> Result<Json<wire::CurrentUser>, crate::AgentError> {
    let input = body(input)?;
    let p = crate::bounded(authenticate_for(
        &app,
        &headers,
        peer.as_ref().map(|p| &p.0),
        &audit,
        false,
    ))
    .await?;
    current_user_stage(&audit, "binding_write");
    let result = app
        .enrollment
        .change_current_user(&p, None, &input, &app.identity, &audit)
        .await;
    current_user_stage(&audit, "binding_finished");
    result.map(Json).map_err(|e| Error::from(e).into())
}

async fn access_begin(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::AccessBegin>,
) -> Result<Response, crate::AgentError> {
    crate::bounded(async {
        let p=authenticate_for(&app,&headers,peer.as_ref().map(|v|&v.0),&audit,false).await?;
        let employee=employee(&app,&headers,&audit).await?.ok_or(Error::Unauthorized)?;
        let input=body(input)?;
        let value=app.enrollment.begin_device_access(&p,&employee,&input,app.execution.as_ref(),&audit).await.map_err(Error::from)?;
        use axum::response::IntoResponse;
        let mut response=Json(serde_json::json!({"id":value.id,"nonce":value.nonce,"expiresAt":value.expires_at,"localSession":value.local_session})).into_response();
        response.headers_mut().insert(axum::http::header::CACHE_CONTROL,axum::http::HeaderValue::from_static("no-store"));
        Ok(response)
    }).await
}
async fn access_confirm(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::AccessConfirm>,
) -> Result<Json<wire::AccessBindingStatus>, crate::AgentError> {
    crate::bounded(async {
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|v| &v.0), &audit, false).await?;
        let employee = employee(&app, &headers, &audit)
            .await?
            .ok_or(Error::Unauthorized)?;
        let input = body(input)?;
        let value = app
            .enrollment
            .confirm_device_access(&p, &employee, &input, app.execution.as_ref(), &audit)
            .await
            .map_err(Error::from)?;
        Ok(Json(value.status()))
    })
    .await
}

async fn access_recovery_use(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::AccessRecoveryUse>,
) -> Result<Json<Value>, crate::AgentError> {
    crate::bounded(async {
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|v| &v.0), &audit, false).await?;
        app.execution
            .record_access_recovery_use(&p, &body(input)?, &audit)
            .await
            .map_err(task_error)?;
        Ok(Json(serde_json::json!({"accepted":true})))
    })
    .await
}

async fn access_directory(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, crate::AgentError> {
    crate::bounded(async {
        use axum::response::IntoResponse;
        let (page, _) = rss_mdm_registration_service::device_access::DISCOVERY
            .parse(raw.as_deref().unwrap_or(""))
            .map_err(|_| Error::Malformed)?;
        let p =
            authenticate_for(&app, &headers, peer.as_ref().map(|v| &v.0), &audit, false).await?;
        let employee = employee(&app, &headers, &audit)
            .await?
            .ok_or(Error::Unauthorized)?;
        let value = app
            .enrollment
            .device_access_directory(&p, &employee, &page, app.execution.as_ref(), &app.identity)
            .await
            .map_err(Error::from)?;
        let mut response = Json(value).into_response();
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        Ok(response)
    })
    .await
}

fn current_user_stage(audit: &RequestAudit, stage: &'static str) {
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_current_user_stage","request_id":audit.request_id(),"stage":stage})
    );
}
