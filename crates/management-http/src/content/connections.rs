use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_content_service::connections::{
    Receipt, Request,
    authority::{Authority, Directory},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<Authority>> {
    Router::new()
        .route("/storage/connections", get(read).post(create))
        .route("/storage/connections/operations/{id}", get(operation))
}
async fn read(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Directory>, Error> {
    audit.set_action("storage_read");
    Ok(Json(service.read(&auth.proof, &audit).await?))
}
async fn create(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Receipt>), Error> {
    let operation = crate::api::write_key(&headers, &audit, "storage_provision")?;
    let input = input.map_err(Error::from)?.0;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            service
                .create(&auth.proof, &audit, operation, &input)
                .await?,
        ),
    ))
}

async fn operation(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Receipt>, Error> {
    audit.set_action("storage_read");
    Ok(Json(service.operation(&auth.proof, &audit, id).await?))
}
