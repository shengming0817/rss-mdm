use crate::execution::http::HttpState;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/policies/{id}/runs", get(runs))
        .route("/policies/{id}/software/rollout", get(rollout))
        .route("/policies/{id}/runs/{task}", get(run))
}
async fn rollout(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    app.execution
        .software_rollout(&auth.proof, id, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
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
        .map_err(Error::from)
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
        .map_err(Error::from)
}

use rss_mdm_audit_integration::RequestAudit;
