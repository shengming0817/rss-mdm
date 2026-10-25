//! Authenticated HTTP adapter for the enterprise software owner.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
type HttpState = rss_mdm_software_service::management::catalog::Access<
    rss_mdm_content_service::software::SoftwareContent,
>;
use rss_mdm_software_service::catalog::{Operation, SourceChange, VersionChange};
use serde_json::Value;
use std::sync::Arc;
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/agent-packages",
            get(managed_packages)
                .owned(&contracts::AGENT_PACKAGES, &[RouteOperation::List])
                .queried(&rss_mdm_software_service::agent_packages::directory::SCHEMA)
                .post(publish_agent)
                .owned(&contracts::AGENT_PACKAGES, &[RouteOperation::Create]),
        )
        .route(
            "/agent-packages/{id}",
            get(managed_package).owned(&contracts::AGENT_PACKAGES, &[RouteOperation::Get]),
        )
        .route(
            "/agent-packages/uploads",
            post(begin_agent_upload).owned(
                &contracts::AGENT_PACKAGES,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
        )
        .route(
            "/agent-packages/uploads/{id}",
            get(inspect_agent_upload)
                .owned(&contracts::AGENT_PACKAGES, &[RouteOperation::Action])
                .post(parse_agent_upload)
                .owned(&contracts::AGENT_PACKAGES, &[RouteOperation::Action]),
        )
        .route(
            "/agent-packages/save",
            post(save_agent_upload).owned(
                &contracts::AGENT_PACKAGES,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
        )
        .route(
            "/agent-packages/operations/{id}",
            get(agent_operation).owned(&contracts::AGENT_PACKAGES, &[RouteOperation::Action]),
        )
        .route(
            "/agent-packages/{id}/withdraw",
            post(withdraw_agent).owned(&contracts::AGENT_PACKAGES, &[RouteOperation::Lifecycle]),
        )
        .route(
            "/software/imports",
            post(import).owned(&contracts::SOFTWARE_VERSIONS, &[RouteOperation::Create]),
        )
        .route(
            "/software/sources",
            get(sources)
                .owned(&contracts::SOFTWARE_SOURCES, &[RouteOperation::List])
                .queried(&rss_mdm_software_service::management::directory::SOURCES),
        )
        .route(
            "/software/resources/{id}/versions/{version}/content",
            get(download).owned(
                &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/software/sources/{id}/revisions/{revision}",
            get(read_source)
                .owned(&contracts::SOFTWARE_SOURCES, &[RouteOperation::Get])
                .post(write_source)
                .owned(
                    &contracts::SOFTWARE_SOURCES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
        )
        .route(
            "/software/resources/{id}/versions",
            get(versions)
                .owned(&contracts::SOFTWARE_VERSIONS, &[RouteOperation::List])
                .queried(&rss_mdm_resource::directory::VERSION_SCHEMA),
        )
        .route(
            "/software/resources/{id}/versions/{version}",
            get(read_version)
                .owned(&contracts::SOFTWARE_VERSIONS, &[RouteOperation::Get])
                .post(write_version)
                .owned(
                    &contracts::SOFTWARE_VERSIONS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
        )
}

async fn managed_packages(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<Json<Value>, Error> {
    let q = rss_mdm_software_service::agent_packages::directory::SCHEMA
        .parse(raw.as_deref().unwrap_or_default())
        .map_err(|_| Error::Malformed)?;
    rss_mdm_software_service::agent_packages::directory::list(&app, &auth.proof, &audit, q)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn managed_package(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Value>, Error> {
    rss_mdm_software_service::agent_packages::directory::get(&app, &auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn versions(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<Json<Value>, Error> {
    let q = rss_mdm_resource::directory::VERSION_SCHEMA
        .parse(raw.as_deref().unwrap_or_default())
        .map_err(|_| Error::Malformed)?;
    rss_mdm_software_service::management::directory::versions(&app, &auth.proof, &audit, &id, q)
        .await
        .map(Json)
        .map_err(Into::into)
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

async fn begin_agent_upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    body: Result<
        Json<rss_mdm_software_service::management::content::PrepareUpload>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<Value>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    rss_mdm_software_service::management::installers::begin(&app, &auth.proof, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn inspect_agent_upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Value>, Error> {
    rss_mdm_software_service::management::installers::inspect(&app, &auth.proof, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn parse_agent_upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Value>, Error> {
    rss_mdm_software_service::management::installers::parse(&app, &auth.proof, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn save_agent_upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_software_service::management::installers::Save>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<Value>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    audit.operation(
        input.operation_id,
        "software_installer_save",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target(&input.package_id.to_string());
    rss_mdm_software_service::management::installers::save(&app, &auth.proof, &audit, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn agent_operation(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Value>, Error> {
    rss_mdm_software_service::management::installers::operation(&app, &auth.proof, id)
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
/// Anonymous, secret-free catalogue shared by Agent HTTPS and browser download ingress.
pub fn agent_packages_public(app: Arc<HttpState>) -> Router {
    Router::new()
        .route(
            "/packages",
            get(agent_package_list).owned(
                &contracts::PROTOCOL_MANAGEMENT_HTTP,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/packages/{id}",
            get(agent_package_metadata).owned(
                &contracts::PROTOCOL_MANAGEMENT_HTTP,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/packages/{id}/content",
            get(agent_package_content).owned(
                &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                &[RouteOperation::Action],
            ),
        )
        .with_state(app)
}
async fn agent_package_list(
    State(app): State<Arc<HttpState>>,
) -> Result<Json<Vec<rss_mdm_agent_wire::enroll::configuration::Package>>, Error> {
    rss_mdm_software_service::agent_packages::list(&app.runtime, app.tenant)
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

async fn sources(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<Json<Value>, Error> {
    let q = rss_mdm_software_service::management::directory::SOURCES
        .parse(raw.as_deref().unwrap_or_default())
        .map_err(|_| Error::Malformed)?;
    rss_mdm_software_service::management::directory::sources(&app, &auth.proof, &audit, q)
        .await
        .map(Json)
        .map_err(Into::into)
}
