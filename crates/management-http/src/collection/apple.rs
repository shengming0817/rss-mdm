use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use rss_mdm_inventory_service::apple_collection::{Create, Service};
use std::sync::Arc;
pub struct HttpState {
    pub service: Service,
}
pub async fn create(
    State(app): State<Arc<HttpState>>,
    Path(device): Path<String>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<rss_mdm_audit_integration::RequestAudit>,
    input: Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<serde_json::Value>), Error> {
    if app.service.participant.is_none() {
        return Err(Error(rss_mdm_flow_service::Error::Unsupported));
    }
    let receipt = rss_mdm_inventory_service::apple_collection::create(
        &app.service,
        &auth.proof,
        device,
        input
            .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?
            .0,
        &audit,
    )
    .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}
