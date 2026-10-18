//! Direct device-scoped credential access; authentication is the normal management middleware.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_recovery_credentials::{Credentials, Material};
use std::sync::Arc;
use uuid::Uuid;

pub fn routes(service: Option<Arc<Credentials>>) -> Router {
    let Some(service) = service else {
        return Router::new();
    };
    Router::new()
        .route("/devices/{device}/recovery-credentials", get(list))
        .route(
            "/devices/{device}/recovery-credentials/{id}/versions/{version}/secret",
            get(disclose),
        )
        .route(
            "/devices/{device}/recovery-credentials/{id}/versions/{version}/revoke",
            post(revoke),
        )
        .with_state(service)
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    after_id: Option<Uuid>,
    after_version: Option<i64>,
}
async fn list(
    State(service): State<Arc<Credentials>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<Material>>, Error> {
    audit.set_action("recovery_credential_list");
    audit.target_device(&device);
    let q = query.map_err(|_| Error::Malformed)?.0;
    let after = match (q.after_id, q.after_version) {
        (None, None) => None,
        (Some(id), Some(v)) if v > 0 => Some((id, v)),
        _ => return Err(Error::Malformed),
    };
    service
        .list(&auth.proof, &device, after)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn disclose(
    State(service): State<Arc<Credentials>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
) -> Result<Response, Error> {
    let value = service
        .disclose(&auth.proof, &device, id, version, &audit)
        .await?;
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}
async fn revoke(
    State(service): State<Arc<Credentials>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
) -> Result<Json<Material>, Error> {
    service
        .revoke(&auth.proof, &device, id, version, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}
