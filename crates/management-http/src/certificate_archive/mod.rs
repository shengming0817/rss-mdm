//! Certificate archive HTTP adapter; no cryptographic or storage decisions live here.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate_archive_service as archive;
use std::sync::Arc;
use uuid::Uuid;

pub fn routes() -> Router<Arc<archive::Archive>> {
    Router::new()
        .route("/certificate-archive/vault", get(state))
        .route("/certificate-archive/vault/initialize", post(initialize))
        .route("/certificate-archive/vault/unlock", post(unlock))
        .route("/certificate-archive/vault/lock", post(lock))
        .route("/certificate-archive/vault/password", post(password))
        .route("/certificate-archive/entries", get(list))
        .route(
            "/certificate-archive/entries/{entry}/versions",
            get(history),
        )
        .route("/certificate-archive/entries/{entry}", put(manage))
        .route(
            "/certificate-archive/entries/{entry}/metadata",
            put(metadata),
        )
        .route(
            "/certificate-archive/import",
            post(import).layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route("/certificate-archive/generate", post(generate))
        .route("/certificate-archive/export", post(export))
        .route(
            "/certificate-archive/settings",
            get(settings).put(change_settings),
        )
        .route(
            "/certificate-archive/operations/{operation}",
            get(operation),
        )
}
fn input<T>(value: Result<Json<T>, axum::extract::rejection::JsonRejection>) -> Result<T, Error> {
    value.map(|v| v.0).map_err(|_| Error::Malformed)
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
    headers: HeaderMap,
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
) -> Result<Json<serde_json::Value>, Error> {
    s.lock(&a.proof)?;
    Ok(Json(serde_json::json!({"locked":true})))
}
async fn password(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    body: Result<Json<archive::ChangePassword>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_password_change")?;
    s.change_password(&a.proof, id, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    after: Option<Uuid>,
}
async fn list(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    q: Result<Query<ListQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<archive::Page>, Error> {
    let q = q.map_err(|_| Error::Malformed)?.0;
    s.list(&a.proof, q.after)
        .await
        .map(Json)
        .map_err(Error::from)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    before: Option<i64>,
}
async fn history(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Path(entry): Path<Uuid>,
    q: Result<Query<HistoryQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<archive::Version>>, Error> {
    let q = q.map_err(|_| Error::Malformed)?.0;
    s.history(&a.proof, entry, q.before)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn import(
    State(s): State<Arc<archive::Archive>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
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
    headers: HeaderMap,
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
    headers: HeaderMap,
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
    headers: HeaderMap,
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
    headers: HeaderMap,
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
    headers: HeaderMap,
    body: Result<Json<archive::ChangeMetadata>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<archive::Receipt>, Error> {
    let id = crate::api::write_key(&headers, &audit, "certificate_archive_metadata")?;
    s.change_metadata(&a.proof, id, entry, input(body)?, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
