//! Apple Platform SSO native protocol and its trusted browser-session adapter.
mod context;
pub mod crypto;
mod status;
mod store;
use context::Context;
pub mod bridge;
pub(crate) mod deployment;
mod http;
mod native;
mod password;
pub mod password_provider;
mod service;
use crate::{Error, HttpState};
pub use http::{agent_routes, browser_routes, management_routes, mount_agent};
use rss_mdm_agent_wire::platform_sso::{Configuration, Endpoints};
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn browser_audience(origin: &str) -> String {
    format!("{origin}/login")
}

/// Deployment-owned signing ring. Dropping a key stops advertising it; no HTTP key upload exists.
pub struct Runtime {
    pub configuration: Configuration,
    pub endpoints: Endpoints,
    browser_audience: String,
    active: String,
    keys: BTreeMap<String, crypto::Signer>,
    pub(super) password_providers: BTreeMap<uuid::Uuid, Arc<password_provider::Provider>>,
}
impl Runtime {
    pub fn new(
        configuration: Configuration,
        origin: &str,
        tenant: uuid::Uuid,
        active: String,
        keys: BTreeMap<String, crypto::Signer>,
    ) -> Result<Self, Error> {
        configuration.validate().map_err(|_| Error::Malformed)?;
        if keys.is_empty() || keys.len() > 4 || !keys.contains_key(&active) {
            return Err(Error::Malformed);
        }
        let endpoints = Endpoints::new(origin, tenant).map_err(|_| Error::Malformed)?;
        let ids = keys
            .values()
            .map(|k| k.id())
            .collect::<std::collections::BTreeSet<_>>();
        if ids.len() != keys.len() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            configuration,
            endpoints,
            browser_audience: browser_audience(origin),
            active,
            keys,
            password_providers: BTreeMap::new(),
        })
    }
    /// Install explicit password capabilities; a browser OIDC configuration is insufficient.
    pub fn with_password_providers(
        mut self,
        providers: Vec<password_provider::Provider>,
    ) -> Result<Self, Error> {
        if providers.len() > 16 {
            return Err(Error::Malformed);
        }
        for provider in providers {
            if self
                .password_providers
                .insert(provider.configuration.id, Arc::new(provider))
                .is_some()
            {
                return Err(Error::Malformed);
            }
        }
        Ok(self)
    }
    pub(super) fn password_provider(
        &self,
        login: &rss_mdm_agent_wire::platform_sso::LoginConfiguration,
    ) -> Result<Arc<password_provider::Provider>, Error> {
        self.password_providers
            .get(&login.password_provider.ok_or(Error::Unsupported)?)
            .cloned()
            .ok_or(Error::Unsupported)
    }
    pub fn fingerprint(&self) -> Result<String, Error> {
        // Deployment identity is independent of each device's Policy-owned login configuration.
        use sha2::Digest;
        let providers = self
            .password_providers
            .iter()
            .map(|(id, p)| Ok((*id, p.fingerprint()?)))
            .collect::<Result<Vec<_>, Error>>()?;
        let bytes = serde_json::to_vec(&(&self.configuration, &self.endpoints, providers))
            .map_err(|_| Error::Malformed)?;
        Ok(crypto::encode(&sha2::Sha256::digest(bytes)))
    }
    pub fn profile_fingerprint(
        &self,
        login: &rss_mdm_agent_wire::platform_sso::LoginConfiguration,
    ) -> Result<String, Error> {
        // Routine signing-key rotation does not revoke device registrations.
        // Hash actual desired payload content using neutral object IDs, so changing a required
        // payload invalidates retained profile qualification without a second format-version knob.
        let (origin, tenant) = self
            .endpoints
            .base
            .split_once("/api/v1/apple/platform-sso/")
            .ok_or(Error::Malformed)?;
        let tenant = uuid::Uuid::parse_str(tenant).map_err(|_| Error::Malformed)?;
        let template = rss_mdm_apple_mdm::platform_sso::profile(
            &self.configuration,
            login,
            origin,
            tenant,
            uuid::Uuid::from_u128(1),
            uuid::Uuid::from_u128(2),
        )?;
        let provider = if login.authentication
            == rss_mdm_agent_wire::platform_sso::AuthenticationMode::Password
        {
            Some(self.password_provider(login)?.fingerprint()?)
        } else {
            None
        };
        let bytes = serde_json::to_vec(&(&self.configuration, &self.endpoints, template, provider))
            .map_err(|_| Error::Malformed)?;
        use sha2::Digest;
        Ok(crypto::encode(&sha2::Sha256::digest(bytes)))
    }
    pub fn qualification_configuration(
        &self,
    ) -> Result<rss_mdm_device_service::personnel::PlatformConfiguration, Error> {
        Ok(rss_mdm_device_service::personnel::PlatformConfiguration {
            configuration: self.fingerprint()?,
            application_id: self.configuration.application_id.clone(),
            application_version: self.configuration.application_version.clone(),
            profile_identifier: format!("rss.platform-sso.{}", self.configuration.client_id),
        })
    }
    /// Public Redirect-extension association, derived only from deployment configuration.
    pub fn association(&self) -> Association {
        Association {
            authsrv: AuthenticationApps {
                apps: vec![format!(
                    "{}.{}",
                    self.configuration.team_id, self.configuration.application_id
                )],
            },
        }
    }
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: self.keys.values().map(|key| key.jwk()).collect(),
        }
    }
    pub fn profile(
        &self,
        login: &rss_mdm_agent_wire::platform_sso::LoginConfiguration,
    ) -> Result<rss_mdm_apple_mdm::native::profiles::ProfileInput, Error> {
        let digest = crypto::decode(&self.profile_fingerprint(login)?)?;
        let id = uuid::Uuid::from_slice(&digest[..16]).map_err(|_| Error::Malformed)?;
        let payload = uuid::Uuid::from_slice(&digest[16..]).map_err(|_| Error::Malformed)?;
        let tenant = uuid::Uuid::parse_str(
            self.endpoints
                .base
                .rsplit('/')
                .next()
                .ok_or(Error::Malformed)?,
        )
        .map_err(|_| Error::Malformed)?;
        let origin = self
            .endpoints
            .base
            .split("/api/")
            .next()
            .ok_or(Error::Malformed)?;
        let mut profile = rss_mdm_apple_mdm::platform_sso::profile(
            &self.configuration,
            login,
            origin,
            tenant,
            id,
            payload,
        )?;
        profile.identifier = format!("rss.platform-sso.{}", self.configuration.client_id);
        Ok(profile)
    }
    fn signer(&self) -> &crypto::Signer {
        &self.keys[&self.active]
    }
}
fn runtime(app: &HttpState) -> Result<&Runtime, Error> {
    app.platform_sso.as_deref().ok_or(Error::Unsupported)
}
pub const INSTALL_SQL: &str = concat!(
    include_str!("../../schema/platform-sso.sql"),
    "\n",
    include_str!("../../schema/platform-qualifications.sql")
);

/// Verify the borrowed Identity runtime's product read/locking privileges at startup.
pub async fn verify_runtime(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(include_str!("runtime-admission.sql"))
        .fetch_one(&mut *c)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "platform runtime privileges rejected".into(),
        ));
    }
    rss_mdm_inventory_postgres::verify_asset_history(c).await
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Association {
    authsrv: AuthenticationApps,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct AuthenticationApps {
    apps: Vec<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Jwks {
    keys: Vec<crypto::SigningJwk>,
}
