//! Product ADE control plane; registration, identity and installed-profile owners stay canonical.
pub(crate) mod authority;
mod client;
pub(crate) mod management;
mod protocol;
pub mod worker;
use crate::{Error, Failure, HttpState, database::db};
use axum::{
    Router,
    routing::{get, post, put},
};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/api/v1/apple/organizations/{id}/ade",
            get(management::status),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/configuration",
            put(management::configure),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/public-key",
            get(management::public_key),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/operations",
            post(management::operation),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/operations/{operation}",
            get(management::operation_status),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/devices",
            get(management::devices),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/profiles",
            get(management::profiles),
        )
        .route(
            "/api/v1/apple/ade/enroll/{organization}/{profile}",
            post(protocol::enroll),
        )
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
}
pub(crate) fn aad(
    tenant: &str,
    organization: Uuid,
    version: &str,
    purpose: &str,
) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        &format!("{organization}:{version}"),
        purpose,
        1,
    )
    .map(|c| c.derive())
    .map_err(|_| Error::Conflict)
}
pub(crate) async fn server(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<sqlx::postgres::PgRow, Error> {
    sqlx::query("SELECT * FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2 FOR UPDATE")
        .bind(tenant).bind(id).fetch_optional(c).await.map_err(db)?.ok_or(Error::NotFound)
}
fn token(
    row: &sqlx::postgres::PgRow,
    app: &HttpState,
    tenant: &str,
    id: Uuid,
) -> Result<client::Token, Error> {
    if !row.try_get::<bool, _>("enabled").map_err(db)?
        || !row.try_get::<bool, _>("verified").map_err(db)?
        || row.try_get::<bool, _>("token_invalid").map_err(db)?
    {
        return Err(Error::Conflict);
    }
    let version: i64 = row.try_get("token_revision").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("token").map_err(db)?;
    let plain = app
        .protection
        .open_bytes(
            &sealed,
            &aad(tenant, id, &version.to_string(), "apple.ade.token")?,
        )
        .map_err(|_| Error::Conflict)?;
    client::Token::parse(plain.expose(), now(app)?)
}
pub(crate) fn now(app: &HttpState) -> Result<i64, Error> {
    app.clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))
}
pub use worker::registration;

#[cfg(feature = "integration")]
#[derive(Clone)]
pub struct Fixture {
    pub client: reqwest::Client,
    pub origin: String,
    pub manufacturer_root: Vec<u8>,
}
