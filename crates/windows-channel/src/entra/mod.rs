//! Product-owned Entra scope, consent and registration authority. Identity owns personnel.
use crate::{Error, HttpState, database::db};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_authorization_service::{
    Permission,
    context::AuthorizedPrincipal,
    entra::{
        self as identity, EntraAuthority, EntraTokenProfile, RevalidatedAccount,
        VerifiedExternalSubject,
    },
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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub provider_id: Uuid,
    pub token: EntraTokenProfile,
}
pub struct Entra {
    pub authority: EntraAuthority,
    tenant: TenantId,
    pub config: Config,
}
impl Entra {
    pub fn new(authority: EntraAuthority, tenant: TenantId, config: Config) -> Result<Self, Error> {
        config.token.validate().map_err(|_| Error::Malformed)?;
        if config.provider_id.is_nil() || config.token.required_scopes.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            authority,
            tenant,
            config,
        })
    }
    async fn verify(&self, token: Zeroizing<String>) -> Result<VerifiedExternalSubject, Error> {
        Ok(identity::verify(&self.authority, token).await?)
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
fn owner(app: &HttpState) -> Result<&Arc<Entra>, Error> {
    app.windows()?.entra.as_ref().ok_or(Error::Unsupported)
}
fn hash(value: &str) -> String {
    crate::enrollment::digest(&("windows.entra.consent/v1", value))
}

mod admission;
mod consent;
mod policy;
mod protocol;
use admission::admit;
use consent::consent;
pub use consent::{Accept, accept, terms};
use policy::settings_in;
pub use policy::{Management, Policy, Revision, Settings, Update};
pub(crate) use protocol::enrollment;
