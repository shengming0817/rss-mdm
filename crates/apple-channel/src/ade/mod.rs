//! Product ADE control plane; registration, identity and installed-profile owners stay canonical.
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
pub(crate) mod authority;
mod client;
pub(crate) mod management;
mod protocol;
pub mod worker;
use crate::{Error, Failure, HttpState, database::db};

use rss_mdm_http_contract::{
    Router,
    routing::{get, post, put},
};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn management_routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct ManagementRoutesModule1 for [Browser] { get_status, put_configure, get_public_key, post_operation, get_operation_status, get_devices, get_profiles } }
        ManagementRoutesModule1 {
            get_status: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/ade",
                get(
                    management::status,
                    &contracts::ADE_CONFIGURATION,
                    &[RouteOperation::Get],
                ),
            ),
            put_configure: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/ade/configuration",
                put(
                    management::configure,
                    &contracts::ADE_CONFIGURATION,
                    &[RouteOperation::Update],
                ),
            ),
            get_public_key: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/ade/public-key",
                get(
                    management::public_key,
                    &contracts::ADE_CONFIGURATION,
                    &[RouteOperation::Get],
                ),
            ),
            post_operation: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/ade/operations",
                post(
                    management::operation,
                    &contracts::ADE_CONFIGURATION,
                    &[RouteOperation::Update],
                ),
            ),
            get_operation_status: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/ade/operations/{operation}",
                get(
                    management::operation_status,
                    &contracts::ADE_CONFIGURATION,
                    &[RouteOperation::Get],
                ),
            ),
            get_devices: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/ade/devices",
                get(
                    management::devices,
                    &contracts::ADE_DEVICES,
                    &[RouteOperation::List],
                ),
            ),
            get_profiles: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/organizations/{id}/ade/profiles",
                get(
                    management::profiles,
                    &contracts::ADE_PROFILES,
                    &[RouteOperation::List],
                ),
            ),
        }
        .assemble()
    }
}
pub(crate) fn routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
 rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { external_post_enroll } }
 RoutesModule1 { external_post_enroll: rss_mdm_http_contract::module::Route::new("/api/v1/apple/ade/enroll/{organization}/{profile}", rss_mdm_http_contract::routing::external_post(
                protocol::enroll,
                rss_mdm_http_contract::ExternalProtocol::AppleMdm, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])) }.assemble()
}
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
