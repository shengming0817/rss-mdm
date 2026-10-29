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
use std::sync::Arc;
pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_managed_packages, post_publish_agent, get_managed_package, post_begin_agent_upload, get_inspect_agent_upload, post_parse_agent_upload, post_save_agent_upload, get_agent_operation, post_withdraw_agent, post_import, get_sources, get_download, get_read_source, post_write_source, get_versions, get_read_version, post_write_version, snapshots } }
        RoutesModule1 {
            snapshots: crate::software_snapshots::routes(),
            get_managed_packages: rss_mdm_http_contract::module::Route::new(
                "/agent-packages",
                rss_mdm_http_contract::routing::get(
                    managed_packages,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::List],
                ),
            ),
            post_publish_agent: rss_mdm_http_contract::module::Route::new(
                "/agent-packages",
                rss_mdm_http_contract::routing::post(
                    publish_agent,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Create],
                ),
            ),
            get_managed_package: rss_mdm_http_contract::module::Route::new(
                "/agent-packages/{id}",
                get(
                    managed_package,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Get],
                ),
            ),
            post_begin_agent_upload: rss_mdm_http_contract::module::Route::new(
                "/agent-packages/uploads",
                post(
                    begin_agent_upload,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            get_inspect_agent_upload: rss_mdm_http_contract::module::Route::new(
                "/agent-packages/uploads/{id}",
                rss_mdm_http_contract::routing::get(
                    inspect_agent_upload,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Action],
                ),
            ),
            post_parse_agent_upload: rss_mdm_http_contract::module::Route::new(
                "/agent-packages/uploads/{id}",
                rss_mdm_http_contract::routing::post(
                    parse_agent_upload,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Action],
                ),
            ),
            post_save_agent_upload: rss_mdm_http_contract::module::Route::new(
                "/agent-packages/save",
                post(
                    save_agent_upload,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            get_agent_operation: rss_mdm_http_contract::module::Route::new(
                "/agent-packages/operations/{id}",
                get(
                    agent_operation,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Action],
                ),
            ),
            post_withdraw_agent: rss_mdm_http_contract::module::Route::new(
                "/agent-packages/{id}/withdraw",
                post(
                    withdraw_agent,
                    &contracts::AGENT_PACKAGES,
                    &[RouteOperation::Lifecycle],
                ),
            ),
            post_import: rss_mdm_http_contract::module::Route::new(
                "/software/imports",
                post(
                    import,
                    &contracts::SOFTWARE_VERSIONS,
                    &[RouteOperation::Create],
                ),
            ),
            get_sources: rss_mdm_http_contract::module::Route::new(
                "/software/sources",
                get(
                    sources,
                    &contracts::SOFTWARE_SOURCES,
                    &[RouteOperation::List],
                ),
            ),
            get_download: rss_mdm_http_contract::module::Route::new(
                "/software/resources/{id}/versions/{version}/content",
                get(
                    download,
                    &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                    &[RouteOperation::Action],
                ),
            ),
            get_read_source: rss_mdm_http_contract::module::Route::new(
                "/software/sources/{id}/revisions/{revision}",
                rss_mdm_http_contract::routing::get(
                    read_source,
                    &contracts::SOFTWARE_SOURCES,
                    &[RouteOperation::Get],
                ),
            ),
            post_write_source: rss_mdm_http_contract::module::Route::new(
                "/software/sources/{id}/revisions/{revision}",
                rss_mdm_http_contract::routing::post(
                    write_source,
                    &contracts::SOFTWARE_SOURCES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
            ),
            get_versions: rss_mdm_http_contract::module::Route::new(
                "/software/resources/{id}/versions",
                get(
                    versions,
                    &contracts::SOFTWARE_VERSIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_read_version: rss_mdm_http_contract::module::Route::new(
                "/software/resources/{id}/versions/{version}",
                rss_mdm_http_contract::routing::get(
                    read_version,
                    &contracts::SOFTWARE_VERSIONS,
                    &[RouteOperation::Get],
                ),
            ),
            post_write_version: rss_mdm_http_contract::module::Route::new(
                "/software/resources/{id}/versions/{version}",
                rss_mdm_http_contract::routing::post(
                    write_version,
                    &contracts::SOFTWARE_VERSIONS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
            ),
        }
        .assemble()
    }
}

async fn managed_packages(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ManagedPackagesQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_software_service::agent_packages::directory::Row,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        rss_mdm_software_service::agent_packages::directory::list(&app, &auth.proof, &audit, q)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn managed_package(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<rss_mdm_software_service::agent_packages::directory::Row>, Error> {
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
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<VersionsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_software_service::management::directory::VersionRow,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        rss_mdm_software_service::management::directory::versions(&app, &auth.proof, &audit, &id, q)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn read_source(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(String, String)>,
) -> Result<Json<rss_mdm_software_service::catalog::SourceView>, Error> {
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
) -> Result<Json<rss_mdm_software_service::catalog::SourceView>, Error> {
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
) -> Result<Json<rss_mdm_software_service::management::catalog::VersionDetail>, Error> {
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
) -> Result<Json<rss_mdm_software_service::catalog::VersionReceipt>, Error> {
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
    crate::content::http::DownloadHeaders(headers): crate::content::http::DownloadHeaders,
) -> Result<rss_mdm_http_contract::download::Download, Error> {
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
) -> Result<Json<rss_mdm_software_service::catalog::ImportReceipt>, Error> {
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
) -> Result<Json<rss_mdm_software_service::management::content::PreparedUpload>, Error> {
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
) -> Result<Json<rss_mdm_software_service::management::content::UploadInspection>, Error> {
    rss_mdm_software_service::management::installers::inspect(&app, &auth.proof, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn parse_agent_upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<rss_mdm_software_service::management::content::UploadInspection>, Error> {
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
) -> Result<Json<rss_mdm_software_service::catalog::InstallerReceipt>, Error> {
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
) -> Result<Json<Option<rss_mdm_software_service::catalog::OperationReceipt>>, Error> {
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
#[derive(schemars::JsonSchema, serde::Deserialize)]
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
) -> Result<rss_mdm_http_contract::signature::WithStatus<204, ()>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    rss_mdm_software_service::agent_packages::withdraw(
        &app,
        &auth.proof,
        id,
        input.operation_id,
        &a,
    )
    .await?;
    Ok(rss_mdm_http_contract::signature::WithStatus(()))
}
/// Anonymous, secret-free catalogue shared by Agent HTTPS and browser download ingress.
pub fn agent_packages_public(
    app: Arc<HttpState>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    mount_agent_packages(Some(app))
}
pub(crate) fn register_agent_packages()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterAgentPackagesModule1 for [Browser, Agent] { get_agent_package_list, get_agent_package_metadata, get_agent_package_content } }
        RegisterAgentPackagesModule1 {
            get_agent_package_list: rss_mdm_http_contract::module::Route::new(
                "/packages",
                get(
                    agent_package_list,
                    &contracts::PROTOCOL_MANAGEMENT_HTTP,
                    &[RouteOperation::Action],
                ),
            ),
            get_agent_package_metadata: rss_mdm_http_contract::module::Route::new(
                "/packages/{id}",
                get(
                    agent_package_metadata,
                    &contracts::PROTOCOL_MANAGEMENT_HTTP,
                    &[RouteOperation::Action],
                ),
            ),
            get_agent_package_content: rss_mdm_http_contract::module::Route::new(
                "/packages/{id}/content",
                get(
                    agent_package_content,
                    &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
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
    crate::content::http::DownloadHeaders(headers): crate::content::http::DownloadHeaders,
) -> Result<
    rss_mdm_http_contract::download::Attachment<rss_mdm_http_contract::download::Download>,
    Error,
> {
    let (package, file) = rss_mdm_software_service::agent_packages::download(&app, id).await?;
    let body = crate::content::http::response(file, &headers).await?;
    let disposition = format!("attachment; filename=\"{}\"", package.filename)
        .parse()
        .map_err(|_| Error::Malformed)?;
    Ok(rss_mdm_http_contract::download::Attachment { body, disposition })
}

async fn sources(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<SourcesQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_software_service::management::directory::SourceRow,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        rss_mdm_software_service::management::directory::sources(&app, &auth.proof, &audit, q)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

struct ManagedPackagesQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ManagedPackagesQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_software_service::agent_packages::directory::SCHEMA
    }
}

struct VersionsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for VersionsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_resource::directory::VERSION_SCHEMA
    }
}

struct SourcesQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for SourcesQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_software_service::management::directory::SOURCES
    }
}

pub fn mount_agent_packages(
    app: Option<Arc<HttpState>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register_agent_packages().bind_with(app.as_ref(), Clone::clone)
}
