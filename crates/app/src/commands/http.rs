use super::*;
use crate::api::{App, RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde_json::Value;
pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/devices/{device}/operations", post(create))
        .route("/devices/{device}/operations/{id}", get(read))
        .route("/devices/{device}/operations/{id}/cancel", post(cancel))
        .route("/devices/{device}/operations/{id}/approve", post(approve))
}
async fn create(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(device): Path<String>,
    Json(input): Json<Create>,
) -> std::result::Result<(StatusCode, Json<Value>), Error> {
    audit.operation(input.operation_id, "command_accept");
    audit.target(&device);
    app.commands
        .create(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
}
async fn read(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((device, id)): Path<(String, Uuid)>,
) -> std::result::Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.target(&device);
    app.commands
        .read(&auth.proof, &device, id, &audit)
        .await
        .map(Json)
}
async fn cancel(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((device, id)): Path<(String, Uuid)>,
    Json(change): Json<Change>,
) -> std::result::Result<Json<Value>, Error> {
    audit.operation(change.request_id, "command_cancel");
    audit.target(&device);
    app.commands
        .change(&auth.proof, &device, id, &change, false, &audit)
        .await
        .map(Json)
}
async fn approve(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((device, id)): Path<(String, Uuid)>,
    Json(change): Json<Change>,
) -> std::result::Result<Json<Value>, Error> {
    audit.operation(change.request_id, "command_approve");
    audit.target(&device);
    app.commands
        .change(&auth.proof, &device, id, &change, true, &audit)
        .await
        .map(Json)
}
