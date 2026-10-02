use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde_json::Value;
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/operations", get(directory))
        .route(
            "/devices/{device}/operations",
            post(create).layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/devices/{device}/operations/{id}", get(read))
        .route("/devices/{device}/operations/{id}/cancel", post(cancel))
        .route("/devices/{device}/operations/{id}/approve", post(approve))
}
async fn directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: std::result::Result<
        Query<rss_mdm_flow_service::execution::directory::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("command_read");
    let Query(q) = query.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    Ok(Json(s.execution.directory(&auth.proof, &q, &audit).await?))
}
async fn create(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: std::result::Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<(StatusCode, Json<Value>), Error> {
    let input = input
        .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?
        .0;
    match input.task.source() {
        rss_mdm_inventory::ReportSource::MdmApple => {
            app.apple()?;
        }
        rss_mdm_inventory::ReportSource::MdmWindows => {
            app.windows()?;
        }
        _ => return Err(Error(rss_mdm_flow_service::Error::Unsupported)),
    }
    audit.operation(input.operation_id, "command_accept");
    audit.target(&device);
    app.execution
        .create(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
        .map_err(Error::from)
}
async fn read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
) -> std::result::Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.target(&device);
    app.execution
        .read(&auth.proof, &device, id, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn cancel(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    input: std::result::Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let change = input
        .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?
        .0;
    audit.operation(change.request_id, "command_cancel");
    audit.target(&device);
    app.execution
        .change(&auth.proof, &device, id, &change, false, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn approve(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    input: std::result::Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let change = input
        .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?
        .0;
    audit.operation(change.request_id, "command_approve");
    audit.target(&device);
    app.execution
        .change(&auth.proof, &device, id, &change, true, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

pub struct HttpState {
    pub execution: std::sync::Arc<crate::execution::ExecutionService>,
    pub apple: bool,
    pub windows: bool,
}
impl HttpState {
    pub fn apple(&self) -> std::result::Result<(), crate::Error> {
        self.apple
            .then_some(())
            .ok_or(crate::Error(rss_mdm_flow_service::Error::Unsupported))
    }
}
impl HttpState {
    pub fn windows(&self) -> std::result::Result<(), crate::Error> {
        self.windows
            .then_some(())
            .ok_or(crate::Error(rss_mdm_flow_service::Error::Unsupported))
    }
}
