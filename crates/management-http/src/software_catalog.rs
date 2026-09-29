//! Authenticated HTTP adapter for the enterprise software owner.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    routing::get,
};
use rss_mdm_audit_integration::RequestAudit;
pub(crate) use rss_mdm_flow_service::software_catalog::Access as HttpState;
use rss_mdm_software_service::catalog::{Operation, SourceChange, VersionChange};
use serde_json::Value;
use std::sync::Arc;
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/software/resources/{id}/versions/{version}/content",
            get(download),
        )
        .route(
            "/software/sources/{id}/revisions/{revision}",
            get(read_source).post(write_source),
        )
        .route(
            "/software/resources/{id}/versions/{version}",
            get(read_version).post(write_version),
        )
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
}

async fn read_source(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    rss_mdm_flow_service::software_catalog::read_source(&app, &auth.proof, &audit, id, revision)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn write_source(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(String, String)>,
    Json(op): Json<Operation<SourceChange>>,
) -> Result<Json<Value>, Error> {
    rss_mdm_flow_service::software_catalog::write_source(
        &app,
        &auth.proof,
        &audit,
        id,
        revision,
        op,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}
async fn read_version(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    rss_mdm_flow_service::software_catalog::read_version(&app, &auth.proof, &audit, id, version)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn write_version(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    Json(op): Json<Operation<VersionChange>>,
) -> Result<Json<Value>, Error> {
    rss_mdm_flow_service::software_catalog::write_version(
        &app,
        &auth.proof,
        &audit,
        id,
        version,
        op,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}

use rss_mdm_flow_service::software_catalog::Selection;
async fn download(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    axum::extract::Query(selection): axum::extract::Query<Selection>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, Error> {
    let content = rss_mdm_flow_service::software_catalog::download(
        &app,
        &auth.proof,
        &audit,
        id,
        version,
        selection,
    )
    .await?;
    crate::content::http::response(content, &headers).await
}
