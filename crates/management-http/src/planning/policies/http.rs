use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
pub fn routes() -> Router<Arc<Policies>> {
    Router::new()
        .route("/policies/previews", post(super::http_preview::preview))
        .route("/policies", get(list))
        .route("/policies/{id}", get(read).post(change))
        .route("/policies/{id}/reruns", post(rerun))
        .route("/policies/{id}/devices", get(devices))
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
    let Json(input) = input.map_err(|_| Error::Malformed)?;
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
    Query(page): Query<Page>,
) -> std::result::Result<Json<Value>, Error> {
    super::read::list(&service, &auth.proof, &audit, page.after)
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
    let Json(input) = input.map_err(|_| Error::Malformed)?;
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
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<DevicePage>,
) -> std::result::Result<Json<Value>, Error> {
    super::read::devices(&service, &auth.proof, &audit, id, page.after)
        .await
        .map(Json)
        .map_err(Error::from)
}
