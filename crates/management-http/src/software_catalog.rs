//! Authenticated HTTP adapter for the enterprise software owner.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use rss_mdm_audit_integration::RequestAudit;
type HttpState = rss_mdm_software_service::management::catalog::Access<
    rss_mdm_content_service::software::SoftwareContent,
>;
use rss_mdm_software_service::catalog::{Operation, SourceChange, VersionChange};
use serde_json::Value;
use std::sync::Arc;
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/agent-packages", post(publish_agent))
        .route("/agent-packages/{id}/withdraw", post(withdraw_agent))
        .route("/software/imports", post(import))
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
}

async fn read_source(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    rss_mdm_software_service::management::catalog::read_source(
        &app,
        &auth.proof,
        &audit,
        id,
        revision,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}
async fn write_source(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(String, String)>,
    body: Result<Json<Operation<SourceChange>>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(op) = body.map_err(Error::from)?;
    rss_mdm_software_service::management::catalog::write_source(
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
    rss_mdm_software_service::management::catalog::read_version(
        &app,
        &auth.proof,
        &audit,
        id,
        version,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}
async fn write_version(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    body: Result<Json<Operation<VersionChange>>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(op) = body.map_err(Error::from)?;
    rss_mdm_software_service::management::catalog::write_version(
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

use rss_mdm_software_service::management::catalog::Selection;
async fn download(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    axum::extract::Query(selection): axum::extract::Query<Selection>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, Error> {
    let content = rss_mdm_software_service::management::catalog::download(
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

async fn import(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: std::result::Result<
        Json<Operation<rss_mdm_software_service::imports::ImportRequest>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<Value>, Error> {
    let Json(op) = body.map_err(Error::from)?;
    rss_mdm_software_service::management::catalog::import(&app, &auth.proof, &audit, op)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn publish_agent(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_software_service::agent_packages::Publish>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_agent_wire::enroll::configuration::Package>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    rss_mdm_software_service::agent_packages::publish(&app, &auth.proof, &input, &a)
        .await
        .map(Json)
        .map_err(Into::into)
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentOperation {
    operation_id: uuid::Uuid,
}
async fn withdraw_agent(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
    body: Result<Json<AgentOperation>, axum::extract::rejection::JsonRejection>,
) -> Result<axum::http::StatusCode, Error> {
    let Json(input) = body.map_err(Error::from)?;
    rss_mdm_software_service::agent_packages::withdraw(
        &app,
        &auth.proof,
        id,
        input.operation_id,
        &a,
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
/// Anonymous, secret-free catalogue on the Agent HTTPS listener.
pub fn agent_packages_public(app: Arc<HttpState>) -> Router {
    Router::new()
        .route("/packages", get(agent_package_list))
        .route("/packages/{id}", get(agent_package_metadata))
        .route("/packages/{id}/content", get(agent_package_content))
        .with_state(app)
}
async fn agent_package_list(
    State(app): State<Arc<HttpState>>,
) -> Result<Json<Vec<rss_mdm_agent_wire::enroll::configuration::Package>>, Error> {
    rss_mdm_software_service::agent_packages::list(&app)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn agent_package_metadata(
    State(app): State<Arc<HttpState>>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<rss_mdm_agent_wire::enroll::configuration::Package>, Error> {
    rss_mdm_software_service::agent_packages::metadata_public(&app, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn agent_package_content(
    State(app): State<Arc<HttpState>>,
    Path(id): Path<uuid::Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, Error> {
    let (package, file) = rss_mdm_software_service::agent_packages::download(&app, id).await?;
    let mut response = crate::content::http::response(file, &headers).await?;
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", package.filename)
            .parse()
            .map_err(|_| Error::Malformed)?,
    );
    Ok(response)
}
