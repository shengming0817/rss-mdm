//! Product-owned Entra scope, consent and registration authority. Identity owns personnel.
use crate::{Error, HttpState, database::db};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_authorization_service::entra::{
    self as identity, EntraAuthority, EntraTokenProfile, RevalidatedAccount,
    VerifiedExternalSubject,
};
use rss_mdm_registration_service::enrollment::{
    WindowsProfile,
    native::{Admission, Coordinates, EntraPolicyAuthority},
};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub provider_id: Uuid,
    pub token: EntraTokenProfile,
    /// Exact native TOU continuation URIs configured for this deployment.
    pub native_callbacks: Vec<String>,
}
pub struct Entra {
    pub authority: EntraAuthority,
    tenant: TenantId,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    pub config: Config,
}
impl Entra {
    pub fn new(
        authority: EntraAuthority,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        config: Config,
    ) -> Result<Self, Error> {
        let tenant = binding.tenant();
        config.token.validate().map_err(|_| Error::Malformed)?;
        if config.provider_id.is_nil() || config.token.required_scopes.is_empty() {
            return Err(Error::Malformed);
        }
        if config.native_callbacks.is_empty()
            || config.native_callbacks.len() > 16
            || config
                .native_callbacks
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != config.native_callbacks.len()
            || config.native_callbacks.iter().any(|uri| {
                if uri.len() > 2048 || uri.contains('#') {
                    return true;
                }
                let Ok(uri) = uri.parse::<axum::http::Uri>() else {
                    return true;
                };
                !matches!(uri.scheme_str(), Some("https" | "ms-appx-web"))
                    || uri.authority().is_none()
                    || uri.query().is_some()
            })
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            authority,
            binding,
            tenant,
            config,
        })
    }
    async fn verify(
        &self,
        token: Zeroizing<String>,
        cutoff: rss_request_context::Deadline,
    ) -> Result<VerifiedExternalSubject, Error> {
        Ok(identity::verify(&self.authority, self.binding, token, cutoff).await?)
    }
}
fn bearer(headers: &axum::http::HeaderMap) -> Result<Zeroizing<String>, Error> {
    if headers.get_all("authorization").iter().count() != 1 {
        return Err(Error::Unauthorized);
    }
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?;
    if value.is_empty() || value.len() > 32768 || value.chars().any(char::is_whitespace) {
        return Err(Error::Unauthorized);
    }
    Ok(Zeroizing::new(value.into()))
}
async fn owner(
    app: &HttpState,
    execution: rss_transactional_messaging::fence::ExecutionBinding,
) -> Result<Arc<Entra>, Error> {
    app.windows(execution)
        .await?
        .entra
        .clone()
        .ok_or(Error::Unsupported)
}
/// Claims only locate an installed verifier; signature, issuer, audience and policy are checked by Identity.
async fn locate(
    app: &HttpState,
    token: &str,
) -> Result<rss_transactional_messaging::fence::ExecutionBinding, Error> {
    use base64::Engine;
    if token.len() > 32768 {
        return Err(Error::Unauthorized);
    }
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Error::Unauthorized);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| Error::Unauthorized)?;
    let claims: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::Unauthorized)?;
    let tenant = claims
        .get("tid")
        .and_then(serde_json::Value::as_str)
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
        .ok_or(Error::Unauthorized)?;
    let audience = claims
        .get("aud")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::Unauthorized)?;
    let tenant = app
        .access
        .locate_entra_profile(tenant, audience)
        .await?
        .ok_or(Error::Unauthorized)?;
    Ok(app.execution(tenant))
}
async fn flow_scope(
    app: &HttpState,
    flow: Uuid,
) -> Result<rss_transactional_messaging::fence::ExecutionBinding, Error> {
    let (tenant, epoch) = app.access.locate_entra_flow(flow).await?;
    Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
        app.storage,
        tenant,
        epoch,
    ))
}
fn hash(value: &str) -> String {
    crate::enrollment::digest(&("windows.entra.consent/v1", value))
}

mod admission;
mod consent;
mod protocol;
use admission::admit;
use consent::consent;
mod web;
pub(crate) use protocol::enrollment;
use rss_mdm_registration_service::windows_entra::{Settings, settings_in};
pub use web::{browser_routes, mount_browser};
