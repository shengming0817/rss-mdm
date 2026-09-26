use crate::planning::actions::model::{Change, Create, CreateInput};
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use rss_mdm_audit_integration::RequestAudit;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct HttpState {
    pub(crate) plans: Arc<crate::flow::actions::ActionWorkflow>,
}
type Body<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(v: Body<T>) -> Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/script-plans", post(create))
        .route("/script-plans/{id}", get(read))
        .route("/script-plans/{id}/approve", post(approve))
        .route("/script-plans/{id}/cancel", post(cancel))
}
async fn create(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    input: Body<CreateInput>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let input = Create::try_from(body(input)?)?;
    audit.operation(input.operation_id, "command_accept");
    audit.plan(input.operation_id);
    app.plans
        .create_action_plan(&auth.proof, &input, &audit)
        .await
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
}
async fn read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.plan(id);
    app.plans
        .read_action_plan(&auth.proof, id, &audit)
        .await
        .map(Json)
}
async fn approve(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<Change>,
) -> Result<Json<Value>, Error> {
    let input = body(input)?;
    audit.operation(input.operation_id, "command_approve");
    audit.plan(id);
    app.plans
        .approve_action_plan(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
}
async fn cancel(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<Change>,
) -> Result<Json<Value>, Error> {
    let input = body(input)?;
    audit.operation(input.operation_id, "command_cancel");
    audit.plan(id);
    app.plans
        .cancel_action_plan(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
}
