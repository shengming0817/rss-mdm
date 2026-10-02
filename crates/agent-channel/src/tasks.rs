use crate::Error;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::HeaderMap,
    response::Response,
    routing::{get, post},
};
use rss_mdm_agent_wire as wire;
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
        .route("/tasks/claim", post(claim))
        .route("/installations/{id}/package", get(installation_package))
        .route(
            "/tasks/{id}/events",
            post(event).layer(DefaultBodyLimit::max(wire::MAX_TASK_REQUEST_BYTES)),
        )
        .route("/tasks/{id}/content", get(download))
}
async fn authenticate(
    app: &TaskState,
    headers: &HeaderMap,
    audit: &RequestAudit,
) -> Result<crate::device::DevicePrincipal, crate::AgentError> {
    let credential = crate::agent_credential(&app.mount, headers)?;
    let (principal, _) = app
        .devices
        .authorize_report(&credential, rss_mdm_inventory::ReportSource::AgentBuiltin)
        .await
        .map_err(|e| task_error(e))?;
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
    if !binding.is_some_and(|b| b.inventory() && b.task()) {
        return Err(task_error(Error::Forbidden));
    }
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
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
    headers: HeaderMap,
    input: Body<wire::TaskClaimRequest>,
) -> Result<Json<Value>, crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let principal = authenticate(&app, &headers, &audit).await?;
        audit.operation(input.operation_id(), "command_read");
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
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Body<wire::TaskEventRequest>,
) -> Result<Json<Value>, crate::AgentError> {
    crate::bounded(async {
        let input = body(input)?;
        let principal = authenticate(&app, &headers, &audit).await?;
        audit.operation(input.operation_id(), "command_accept");
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
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<Download>,
) -> Result<Response, crate::AgentError> {
    crate::bounded(async {
        let principal = authenticate(&app, &headers, &audit).await?;
        audit.operation(id, "command_read");
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
    pub mount: crate::device::ChannelMount,
    pub devices: Arc<crate::device::DeviceService>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
}

async fn installation_package(
    State(app): State<Arc<TaskState>>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, crate::AgentError> {
    let content = app
        .execution
        .installation_content(id, &audit)
        .await
        .map_err(task_error)?;
    crate::content::response(content, &headers)
        .await
        .map_err(task_error)
}
