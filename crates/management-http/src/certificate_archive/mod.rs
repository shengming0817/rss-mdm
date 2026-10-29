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

pub fn routes(
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<archive::Archive>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some(cursor))
}
pub(crate) fn register(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<archive::Archive>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_state, post_initialize, post_unlock, post_lock, post_password, get_list, get_history, get_detail, put_manage, put_metadata, post_import, post_generate, post_export, get_settings, put_change_settings, get_operation } }
        RegisterModule1 {
            get_state: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/vault",
                get(state, &contracts::CERTIFICATE_VAULT, &[RouteOperation::Get]),
            ),
            post_initialize: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/vault/initialize",
                post(
                    initialize,
                    &contracts::CERTIFICATE_VAULT,
                    &[RouteOperation::Update],
                ),
            ),
            post_unlock: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/vault/unlock",
                post(
                    unlock,
                    &contracts::CERTIFICATE_VAULT,
                    &[RouteOperation::Update],
                ),
            ),
            post_lock: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/vault/lock",
                post(
                    lock,
                    &contracts::CERTIFICATE_VAULT,
                    &[RouteOperation::Update],
                ),
            ),
            post_password: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/vault/password",
                post(
                    password,
                    &contracts::CERTIFICATE_VAULT,
                    &[RouteOperation::Update],
                ),
            ),
            get_list: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/entries",
                get(list, &contracts::CERTIFICATES, &[RouteOperation::List]),
            ),
            get_history: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/entries/{entry}/versions",
                get(
                    history,
                    &contracts::CERTIFICATE_VERSIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_detail: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/entries/{entry}",
                rss_mdm_http_contract::routing::get(
                    detail,
                    &contracts::CERTIFICATES,
                    &[RouteOperation::Get],
                ),
            ),
            put_manage: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/entries/{entry}",
                rss_mdm_http_contract::routing::put(
                    manage,
                    &contracts::CERTIFICATES,
                    &[RouteOperation::Lifecycle],
                ),
            ),
            put_metadata: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/entries/{entry}/metadata",
                put(
                    metadata,
                    &contracts::CERTIFICATES,
                    &[RouteOperation::Action, RouteOperation::Update],
                ),
            ),
            post_import: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/import",
                post(import, &contracts::CERTIFICATES, &[RouteOperation::Create]),
            ),
            post_generate: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/generate",
                post(
                    generate,
                    &contracts::CERTIFICATES,
                    &[RouteOperation::Create],
                ),
            ),
            post_export: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/export",
                post(export, &contracts::CERTIFICATES, &[RouteOperation::Action]),
            ),
            get_settings: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/settings",
                rss_mdm_http_contract::routing::get(
                    settings,
                    &contracts::CERTIFICATE_SETTINGS,
                    &[RouteOperation::Get],
                ),
            ),
            put_change_settings: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/settings",
                rss_mdm_http_contract::routing::put(
                    change_settings,
                    &contracts::CERTIFICATE_SETTINGS,
                    &[RouteOperation::Update],
                ),
            ),
            get_operation: rss_mdm_http_contract::module::Route::new(
                "/certificate-archive/operations/{operation}",
                get(
                    operation,
                    &contracts::CERTIFICATE_OPERATIONS,
                    &[RouteOperation::Get],
                ),
            ),
        }
        .assemble()
    };
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
