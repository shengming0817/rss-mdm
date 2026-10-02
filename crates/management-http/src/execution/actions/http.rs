use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use rss_mdm_execution_service::queries::Queries;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub fn routes() -> Router<Arc<Queries>> {
    Router::new()
        .route("/policies/{id}/runs", get(runs))
        .route("/policies/{id}/software/rollout", get(rollout))
        .route("/policies/{id}/runs/{task}", get(run))
}
async fn rollout(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    app.software_rollout(&auth.proof, id, &audit)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution facts serialize")))
        .map_err(Error::from)
}

async fn runs(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<super::history::Page>,
) -> Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.plan(id);
    app.action_runs(&auth.proof, id, &page, &audit)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution facts serialize")))
        .map_err(Error::from)
}
async fn run(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, Error> {
    audit.operation(task, "command_read");
    audit.plan(id);
    audit.target(&task.to_string());
    app.action_run(&auth.proof, id, task, &audit)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution facts serialize")))
        .map_err(Error::from)
}

use rss_mdm_audit_integration::RequestAudit;
