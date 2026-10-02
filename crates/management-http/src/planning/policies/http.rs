use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use std::sync::Arc;
type Page = rss_mdm_flow_service::planning::policies::read::DirectoryQuery;
pub fn routes(queries: Arc<rss_mdm_execution_service::queries::Queries>) -> Router<Arc<Policies>> {
    Router::new()
        .merge(
            Router::new()
                .route("/policies/previews", post(super::http_preview::preview))
                .route("/policies/{id}/devices", get(devices))
                .with_state(queries),
        )
        .route("/policies", get(list))
        .route("/policies/{id}", get(read).post(change))
        .route("/policies/{id}/reruns", post(rerun))
}
async fn change(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<crate::http_operation::Operation<Change>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = input.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    audit.operation(input.operation_id, "management_write");
    audit.target(&id.to_string());
    service
        .change(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn read(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<Value>, Error> {
    super::read::read(&service, &auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn list(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    page: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let Query(page) = page.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    super::read::list(&service, &auth.proof, &audit, &page)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn rerun(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<crate::http_operation::Operation<super::rerun::Rerun>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = input.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    audit.operation(input.operation_id, "management_write");
    audit.target(&id.to_string());
    service
        .rerun(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DevicePage {
    after: Option<String>,
}
async fn devices(
    State(service): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<DevicePage>,
) -> std::result::Result<Json<Value>, Error> {
    rss_mdm_execution_service::queries::assignments::devices(
        &service,
        &auth.proof,
        &audit,
        id,
        page.after,
    )
    .await
    .map(|v| Json(serde_json::to_value(v).expect("assignment facts serialize")))
    .map_err(Error::from)
}
