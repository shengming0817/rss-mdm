use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<String>,
}
// Historical reads and cancellation cannot recreate the retired execution source.
pub fn routes(
    queries: Arc<rss_mdm_execution_service::queries::Queries>,
) -> Router<Arc<ExecutionService>> {
    Router::new()
        .merge(
            Router::new()
                .route("/remote-operations", get(directory))
                .route("/remote-operations/{id}", get(read))
                .route("/remote-operations/{id}/runs/{run}", get(run_detail))
                .with_state(queries),
        )
        .route("/remote-operations/{id}/cancel", post(cancel))
}

async fn directory(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<
        Query<rss_mdm_execution_service::remote_operations::directory::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Query(q) = query.map_err(|_| Error::Malformed)?;
    Ok(Json(crate::execution::projection::remote_directory(
        rss_mdm_execution_service::remote_operations::directory::list(&s, &auth.proof, &q, &audit)
            .await?,
    )))
}
async fn read(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> std::result::Result<Json<Value>, Error> {
    super::read::read(&s, &a.proof, &audit, id, page.after)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("remote execution facts serialize")))
        .map_err(Error::from)
}
use super::read::Cancel;
async fn cancel(
    State(s): State<Arc<ExecutionService>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<Json<Cancel>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = body.map_err(|_| Error::Malformed)?;
    super::read::cancel(&s, &a.proof, &audit, id, &input)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn run_detail(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, run)): Path<(Uuid, Uuid)>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("command_read");
    audit.target(&run.to_string());
    s.remote_action_run(&a.proof, id, run, &audit)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("remote execution facts serialize")))
        .map_err(Error::from)
}
