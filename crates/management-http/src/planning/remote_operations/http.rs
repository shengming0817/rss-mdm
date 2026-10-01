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
pub fn routes() -> Router<Arc<Policies>> {
    Router::new()
        .route("/remote-operations", post(create).get(directory))
        .route("/remote-operations/{id}", get(read))
        .route("/remote-operations/{id}/cancel", post(cancel))
        .route("/remote-operations/{id}/runs/{run}", get(run_detail))
}

async fn directory(
    State(s): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<
        Query<rss_mdm_flow_service::planning::remote_operations::directory::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Query(q) = query.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    Ok(Json(
        rss_mdm_flow_service::planning::remote_operations::directory::list(
            &s,
            &auth.proof,
            &q,
            &audit,
        )
        .await?,
    ))
}
async fn create(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: std::result::Result<Json<Input>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = body.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    if input.operation_id.is_nil() {
        return Err(Error(rss_mdm_flow_service::Error::Malformed));
    }
    audit.operation(input.operation_id, "management_write");
    audit.target(&input.operation_id.to_string());
    s.create_remote(&a.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn read(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> std::result::Result<Json<Value>, Error> {
    super::read::read(&s, &a.proof, &audit, id, page.after)
        .await
        .map(Json)
        .map_err(Error::from)
}
use super::read::Cancel;
async fn cancel(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<Json<Cancel>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = body.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    super::read::cancel(&s, &a.proof, &audit, id, &input)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn run_detail(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, run)): Path<(Uuid, Uuid)>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("command_read");
    audit.target(&run.to_string());
    s.execution
        .remote_action_run(&a.proof, id, run, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
