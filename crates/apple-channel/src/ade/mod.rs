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

pub(crate) fn management_routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/api/v1/apple/organizations/{id}/ade",
            get(management::status).owned(&contracts::ADE_CONFIGURATION, &[RouteOperation::Get]),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/configuration",
            put(management::configure)
                .owned(&contracts::ADE_CONFIGURATION, &[RouteOperation::Update]),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/public-key",
            get(management::public_key)
                .owned(&contracts::ADE_CONFIGURATION, &[RouteOperation::Get]),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/operations",
            post(management::operation)
                .owned(&contracts::ADE_CONFIGURATION, &[RouteOperation::Update]),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/operations/{operation}",
            get(management::operation_status)
                .owned(&contracts::ADE_CONFIGURATION, &[RouteOperation::Get]),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/devices",
            get(management::devices)
                .owned(&contracts::ADE_DEVICES, &[RouteOperation::List])
                .queried(&crate::management_query::DEVICES),
        )
        .route(
            "/api/v1/apple/organizations/{id}/ade/profiles",
            get(management::profiles)
                .owned(&contracts::ADE_PROFILES, &[RouteOperation::List])
                .queried(&crate::management_query::PROFILES),
        )
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/api/v1/apple/ade/enroll/{organization}/{profile}",
            post(protocol::enroll).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
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

/// Legal directory preparation for consumers whose action starts after ADE setup.
/// No successful operation, enrollment, receipt or audit record is manufactured.
#[cfg(feature = "integration")]
pub mod fixture {
    use super::*;
    pub struct Directory<'a> {
        pub tenant: &'a str,
        pub organization: Uuid,
        pub profile: Uuid,
        pub remote_profile: Uuid,
        pub serial: &'a str,
        pub token: &'a [u8],
        pub configuration: serde_json::Value,
        pub origin: &'a str,
        pub now: i64,
    }
    pub async fn seed_in(
        c: &mut sqlx::PgConnection,
        protection: &rss_mdm_native_protection::Protector,
        input: Directory<'_>,
    ) -> Result<serde_json::Value, Error> {
        let Directory {
            tenant,
            organization,
            profile,
            remote_profile,
            serial,
            token,
            configuration,
            origin,
            now,
        } = input;
        let token = client::Token::parse(token, now)?;
        let setup: management::Setup =
            serde_json::from_value(configuration.clone()).map_err(|_| Error::Malformed)?;
        setup.validate()?;
        crate::organizations::ensure_in(c, tenant, organization).await?;
        let key = rss_mdm_certificate::apple::ade::generate_key(now)?;
        let key_id = Uuid::new_v4();
        let private = protection
            .seal_bytes(
                &key.private_key,
                &aad(tenant, organization, &key_id.to_string(), "apple.ade.key")?,
            )
            .map_err(|_| Error::Conflict)?;
        let sealed = protection
            .seal_bytes(
                &serde_json::to_vec(&token).map_err(|_| Error::Malformed)?,
                &aad(tenant, organization, "1", "apple.ade.token")?,
            )
            .map_err(|_| Error::Conflict)?;
        sqlx::query("INSERT INTO mdm_apple.ade_servers(tenant_id,organization,revision,enabled,server_uuid,org_id,key_id,certificate,private_key,token,token_revision,token_expires,verified,cursor,synced_at,next_sync) VALUES($1::uuid,$2,1,true,$2,'T2-organization',$3,$4,$5,$6,1,$7,true,'page-2',$8,$8+3600)")
            .bind(tenant).bind(organization).bind(key_id).bind(key.certificate).bind(private).bind(sealed).bind(token.expires()?).bind(now).execute(&mut *c).await.map_err(db)?;
        sqlx::query("INSERT INTO mdm_apple.ade_profiles(tenant_id,organization,id,revision,configuration,remote_uuid) VALUES($1::uuid,$2,$3,1,$4,$5)")
            .bind(tenant).bind(organization).bind(profile).bind(configuration).bind(remote_profile).execute(&mut *c).await.map_err(db)?;
        sqlx::query("INSERT INTO mdm_apple.ade_devices(tenant_id,organization,serial,operation_date,deleted,seen_run,remote_profile,observed_at) VALUES($1::uuid,$2,$3,'2026-10-01T00:00:00.123456Z',false,$4,$5,$6)")
            .bind(tenant).bind(organization).bind(serial).bind(Uuid::new_v4()).bind(remote_profile).bind(now).execute(c).await.map_err(db)?;
        Ok(setup.apple(format!(
            "{origin}/api/v1/apple/ade/enroll/{organization}/{profile}"
        )))
    }
}
