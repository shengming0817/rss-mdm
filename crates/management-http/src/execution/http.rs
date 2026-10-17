use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use rss_mdm_execution_service::{
    Change,
    device_control::{Input, Reauthorization},
};
use serde_json::Value;
pub fn routes(queries: Arc<rss_mdm_execution_service::queries::Queries>) -> Router<Arc<HttpState>> {
    Router::new()
        .merge(
            Router::new()
                .route("/operations", get(directory))
                .route("/devices/{device}/operations/{id}", get(read))
                .with_state(queries),
        )
        .route("/devices/{device}/operations", post(create))
        .route("/devices/{device}/operations/{id}/cancel", post(cancel))
        .route(
            "/devices/{device}/operations/{id}/reauthorize",
            post(reauthorize),
        )
}
async fn directory(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: std::result::Result<
        Query<rss_mdm_execution_service::directory::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("command_read");
    let Query(q) = query.map_err(|_| Error::Malformed)?;
    Ok(Json(crate::execution::projection::directory(
        s.directory(&auth.proof, &q, &audit).await?,
    )))
}
async fn create(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: std::result::Result<Json<Input>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<(StatusCode, Json<Value>), Error> {
    let input = input.map_err(Error::from)?.0;
    audit.operation(input.operation_id, "command_accept");
    audit.target(&device);
    app.execution
        .create_control(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
        .map_err(Error::from)
}
async fn read(
    State(app): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
) -> std::result::Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.target(&device);
    app.read(&auth.proof, &device, id, &audit)
        .await
        .map(|v| Json(crate::execution::projection::command(v)))
        .map_err(Error::from)
}
async fn cancel(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    input: std::result::Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let change = input.map_err(Error::from)?.0;
    audit.operation(change.request_id, "command_cancel");
    audit.target(&device);
    app.execution
        .change(&auth.proof, &device, id, &change, None, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn reauthorize(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    input: std::result::Result<Json<Reauthorization>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let change = input.map_err(Error::from)?.0;
    let revision = Change {
        request_id: change.request_id,
        expected_revision: change.expected_revision,
    };
    audit.operation(change.request_id, "command_reauthorize");
    audit.target(&device);
    app.execution
        .change(&auth.proof, &device, id, &revision, Some(&change), &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

pub struct HttpState {
    pub execution: std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
    pub apple: bool,
    pub windows: bool,
}
impl HttpState {
    pub fn apple(&self) -> std::result::Result<(), crate::Error> {
        self.apple.then_some(()).ok_or(crate::Error::Unsupported)
    }
}
impl HttpState {
    pub fn windows(&self) -> std::result::Result<(), crate::Error> {
        self.windows.then_some(()).ok_or(crate::Error::Unsupported)
    }
}
