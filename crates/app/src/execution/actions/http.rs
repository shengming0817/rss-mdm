use crate::execution::http::HttpState;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_mdm_agent_wire as wire;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

type Body<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(v: Body<T>) -> Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/script-plans/{id}/runs", get(runs))
        .route("/script-plans/{id}/runs/{task}", get(run))
}
pub(crate) fn agent_routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/tasks/claim", post(claim))
        .route(
            "/tasks/{id}/events",
            post(event).layer(DefaultBodyLimit::max(wire::MAX_TASK_REQUEST_BYTES)),
        )
        .route("/tasks/{id}/content", get(download))
}

async fn runs(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<super::history::Page>,
) -> Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.plan(id);
    app.execution
        .action_runs(&auth.proof, id, &page, &audit)
        .await
        .map(Json)
}
async fn run(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, Error> {
    audit.operation(task, "command_read");
    audit.plan(id);
    audit.target(&task.to_string());
    app.execution
        .action_run(&auth.proof, id, task, &audit)
        .await
        .map(Json)
}

async fn authenticate(
    app: &HttpState,
    headers: &HeaderMap,
    audit: &RequestAudit,
) -> Result<crate::device::DevicePrincipal, crate::agent::AgentError> {
    let credential = crate::agent::agent_credential(app.execution.tenant, headers)?;
    let principal = app
        .devices
        .authorize_task(&credential)
        .await
        .map_err(task_error)?;
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
    Ok(principal)
}
fn task_error(error: Error) -> crate::agent::AgentError {
    match error {
        Error::Forbidden => crate::agent::AgentError::Wire(wire::ErrorCode::PermissionDenied),
        error if error.is_not_found() => {
            crate::agent::AgentError::Wire(wire::ErrorCode::TaskNotFound)
        }
        other => other.into(),
    }
}
async fn claim(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Body<wire::TaskClaimRequest>,
) -> Result<Json<Value>, crate::agent::AgentError> {
    crate::agent::bounded(async {
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
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Body<wire::TaskEventRequest>,
) -> Result<Json<Value>, crate::agent::AgentError> {
    crate::agent::bounded(async {
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
}
async fn download(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<Download>,
) -> Result<Response, crate::agent::AgentError> {
    crate::agent::bounded(async {
        let principal = authenticate(&app, &headers, &audit).await?;
        audit.operation(id, "command_read");
        let (bytes, etag) = app
            .execution
            .action_content(&principal, id, query.attempt, &audit)
            .await
            .map_err(task_error)?;
        if headers.get_all(header::RANGE).iter().count() > 1 {
            return Err(Error::Malformed.into());
        }
        let requested = headers
            .get(header::RANGE)
            .map(|h| h.to_str().map_err(|_| Error::Malformed))
            .transpose()?;
        let requested = if headers
            .get(header::IF_RANGE)
            .is_some_and(|value| value.as_bytes() != etag.as_bytes())
        {
            None
        } else {
            requested
        };
        let (start, end) = match crate::task_content::range(requested, bytes.len()) {
            Ok(range) => range,
            Err(_) => {
                let mut response = (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    Json(wire::ErrorBody {
                        code: wire::ErrorCode::RangeNotSatisfiable,
                    }),
                )
                    .into_response();
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    format!("bytes */{}", bytes.len())
                        .parse()
                        .map_err(|_| Error::Malformed)?,
                );
                return Ok(response);
            }
        };
        let mut response = (
            if requested.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            },
            bytes[start..end].to_vec(),
        )
            .into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/octet-stream".parse().expect("constant"),
        );
        response
            .headers_mut()
            .insert(header::ETAG, etag.parse().map_err(|_| Error::Malformed)?);
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, "bytes".parse().expect("constant"));
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            "private, no-store".parse().expect("constant"),
        );
        if requested.is_some() {
            response.headers_mut().insert(
                header::CONTENT_RANGE,
                format!("bytes {start}-{}/{}", end - 1, bytes.len())
                    .parse()
                    .map_err(|_| Error::Malformed)?,
            );
        }
        Ok(response)
    })
    .await
}

use rss_mdm_audit_integration::RequestAudit;
