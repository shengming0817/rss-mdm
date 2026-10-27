//! Certificate archive HTTP adapter; no cryptographic or storage decisions live here.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate_archive_service as archive;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post, put},
};
use std::sync::Arc;
use uuid::Uuid;

pub fn routes(cursor: rss_mdm_query::cursor::CursorCodec) -> Router<Arc<archive::Archive>> {
    register(Some(cursor))
}
pub(crate) fn register(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<archive::Archive>> {
    let router = Router::new()
        .route(
            "/certificate-archive/vault",
            get(state).owned(&contracts::CERTIFICATE_VAULT, &[RouteOperation::Get]),
        )
        .route(
            "/certificate-archive/vault/initialize",
            post(initialize).owned(&contracts::CERTIFICATE_VAULT, &[RouteOperation::Update]),
        )
        .route(
            "/certificate-archive/vault/unlock",
            post(unlock).owned(&contracts::CERTIFICATE_VAULT, &[RouteOperation::Update]),
        )
        .route(
            "/certificate-archive/vault/lock",
            post(lock).owned(&contracts::CERTIFICATE_VAULT, &[RouteOperation::Update]),
        )
        .route(
            "/certificate-archive/vault/password",
            post(password).owned(&contracts::CERTIFICATE_VAULT, &[RouteOperation::Update]),
        )
        .route(
            "/certificate-archive/entries",
            get(list).owned(&contracts::CERTIFICATES, &[RouteOperation::List]),
        )
        .route(
            "/certificate-archive/entries/{entry}/versions",
            get(history).owned(&contracts::CERTIFICATE_VERSIONS, &[RouteOperation::List]),
        )
        .route(
            "/certificate-archive/entries/{entry}",
            get(detail)
                .owned(&contracts::CERTIFICATES, &[RouteOperation::Get])
                .put(manage)
                .owned(&contracts::CERTIFICATES, &[RouteOperation::Lifecycle]),
        )
        .route(
            "/certificate-archive/entries/{entry}/metadata",
            put(metadata).owned(
                &contracts::CERTIFICATES,
                &[RouteOperation::Action, RouteOperation::Update],
            ),
        )
        .route(
            "/certificate-archive/import",
            post(import).owned(&contracts::CERTIFICATES, &[RouteOperation::Create]),
        )
        .route(
            "/certificate-archive/generate",
            post(generate).owned(&contracts::CERTIFICATES, &[RouteOperation::Create]),
        )
        .route(
            "/certificate-archive/export",
            post(export).owned(&contracts::CERTIFICATES, &[RouteOperation::Action]),
        )
        .route(
            "/certificate-archive/settings",
            get(settings)
                .owned(&contracts::CERTIFICATE_SETTINGS, &[RouteOperation::Get])
                .put(change_settings)
                .owned(&contracts::CERTIFICATE_SETTINGS, &[RouteOperation::Update]),
        )
        .route(
            "/certificate-archive/operations/{operation}",
            get(operation).owned(&contracts::CERTIFICATE_OPERATIONS, &[RouteOperation::Get]),
        );
    match cursor {
        Some(cursor) => router.layer(axum::Extension(cursor)),
        None => router,
    }
}
fn input<T>(value: Result<Json<T>, axum::extract::rejection::JsonRejection>) -> Result<T, Error> {
    value.map(|v| v.0).map_err(Error::from)
}
async fn state(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
) -> Result<Json<archive::VaultState>, Error> {
    s.state(&a.proof).await.map(Json).map_err(Error::from)
}
async fn initialize(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::PasswordInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_initialize")?;
    s.initialize(&a.proof, id, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn unlock(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    body: Result<Json<archive::PasswordInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::VaultState>, Error> {
    s.unlock(&a.proof, input(body)?)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn lock(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
) -> Result<Json<Locked>, Error> {
    s.lock(&a.proof)?;
    Ok(Json(Locked { locked: true }))
}
async fn password(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::ChangePassword>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_password_change")?;
    s.change_password(&a.proof, id, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn list(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(cursor): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ListQuery>,
    >,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<archive::Page>>, Error> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        s.list(&a.proof, &q, &cursor)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn detail(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Path(entry): Path<Uuid>,
) -> Result<Json<archive::Entry>, Error> {
    s.entry(&a.proof, entry)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn history(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Path(entry): Path<Uuid>,
    Extension(cursor): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<HistoryQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<Json<rss_mdm_query::Page<archive::Version>>>,
    Error,
> {
    (async {
        let (q, _) = query.parse().map_err(|_| Error::Malformed)?;
        s.history(&a.proof, entry, &q, &cursor)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn import(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::Import>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_import")?;
    s.import(&a.proof, id, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn generate(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::Generate>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_generate")?;
    s.generate(&a.proof, id, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn export(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::VersionRef>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Export>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_export")?;
    s.export(&a.proof, id, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn operation(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<archive::Receipt>, Error> {
    s.operation(&a.proof, id)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn settings(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
) -> Result<Json<archive::SettingsView>, Error> {
    s.settings(&a.proof).await.map(Json).map_err(Error::from)
}
async fn change_settings(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::ChangeSettings>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_settings")?;
    s.change_settings(&a.proof, id, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn manage(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(entry): Path<Uuid>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::ManageEntry>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_manage")?;
    s.manage(&a.proof, id, entry, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn metadata(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(entry): Path<Uuid>,
    headers: crate::api::WriteHeaders,
    body: Result<Json<archive::ChangeMetadata>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_metadata")?;
    s.change_metadata(&a.proof, id, entry, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

struct ListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &archive::directory::SCHEMA
    }
}

struct HistoryQuery;
impl rss_mdm_http_contract::query::WindowOwner for HistoryQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &archive::directory::HISTORY
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct Locked {
    #[schemars(extend("const"=true))]
    locked: bool,
}
