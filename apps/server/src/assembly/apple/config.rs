use crate::{ConfigIssue, Error, native::PublicEndpoint};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub platform_sso: Option<PlatformSso>,
    #[cfg(test)]
    #[serde(skip)]
    pub test_push_transport: Option<(String, PathBuf)>,
    pub management: PublicEndpoint,
    #[serde(default)]
    pub trust_file: PathBuf,
    #[serde(default)]
    pub materials: rss_mdm_apple_channel::runtime_materials::runtime::Selection,
    #[serde(default = "unconfigured_seed")]
    pub identity_seed: rss_mdm_apple_channel::IdentitySeed,
    #[serde(default)]
    pub webhooks: Vec<crate::ca_webhooks::Credentials>,
}
impl Config {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
        let _ = browser;
        let bad = |issue| Error::Configuration(issue);
        let endpoint = crate::config::https_url(&self.management.origin)
            .map_err(|_| bad(ConfigIssue::AppleListeners))?;
        if endpoint.origin().ascii_serialization() != self.management.origin {
            return Err(bad(ConfigIssue::AppleListeners));
        }
        if self.materials.apns.is_some_and(|v| v < 1)
            || self.materials.profile.is_some_and(|v| v < 1)
            || self.materials.accounts.len() > 16
        {
            return Err(bad(ConfigIssue::AppleApns));
        }
        let valid = |id: &str| {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        };
        if (!self.identity_seed.challenge_id.is_empty() && !valid(&self.identity_seed.challenge_id))
            || (!self.identity_seed.notify_id.is_empty() && !valid(&self.identity_seed.notify_id))
            || (!self.identity_seed.challenge_id.is_empty()
                && self.identity_seed.challenge_id == self.identity_seed.notify_id)
        {
            return Err(bad(ConfigIssue::AppleChallengeWebhook));
        }
        Ok(())
    }
}

fn unconfigured_seed() -> rss_mdm_apple_channel::IdentitySeed {
    rss_mdm_apple_channel::IdentitySeed {
        challenge_id: String::new(),
        notify_id: String::new(),
    }
}

#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformSso {
    pub configuration: rss_mdm_agent_wire::platform_sso::Configuration,
    pub active_key: String,
    pub signing_keys: std::collections::BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub password_providers: Vec<PasswordProvider>,
}
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordProvider {
    pub configuration: rss_mdm_apple_channel::platform_sso::password_provider::Configuration,
    pub client_secret_file: PathBuf,
    pub private_ca_file: Option<PathBuf>,
}
impl PlatformSso {
    pub(crate) fn load(
        &self,
        origin: &str,
        tenant: rss_request_context::TenantId,
    ) -> Result<std::sync::Arc<rss_mdm_apple_channel::platform_sso::Runtime>, Error> {
        let mut keys = std::collections::BTreeMap::new();
        for (name, path) in &self.signing_keys {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err(Error::Configuration(ConfigIssue::ApplePlatformSso));
            }
            let bytes = crate::config::read(path, 16384, true)?;
            keys.insert(
                name.clone(),
                rss_mdm_apple_channel::platform_sso::crypto::Signer::from_pem(&bytes)
                    .map_err(|_| Error::Configuration(ConfigIssue::ApplePlatformSso))?,
            );
        }
        let tenant = uuid::Uuid::parse_str(&tenant.to_string())
            .map_err(|_| Error::Configuration(ConfigIssue::ApplePlatformSso))?;
        let mut providers = Vec::new();
        for config in &self.password_providers {
            let bytes = crate::config::read(&config.client_secret_file, 4096, true)?;
            let secret = zeroize::Zeroizing::new(
                std::str::from_utf8(&bytes)
                    .map_err(|_| Error::Configuration(ConfigIssue::ApplePlatformSso))?
                    .trim_end()
                    .to_owned(),
            );
            let ca = config
                .private_ca_file
                .as_ref()
                .map(|path| crate::config::read(path, 65536, false))
                .transpose()?;
            providers.push(
                rss_mdm_apple_channel::platform_sso::password_provider::Provider::new(
                    config.configuration.clone(),
                    secret,
                    ca.as_deref().map(|v| v.as_slice()),
                )
                .map_err(|_| Error::Configuration(ConfigIssue::ApplePlatformSso))?,
            );
        }
        Ok(std::sync::Arc::new(
            rss_mdm_apple_channel::platform_sso::Runtime::new(
                self.configuration.clone(),
                origin,
                tenant,
                self.active_key.clone(),
                keys,
            )
            .and_then(|runtime| runtime.with_password_providers(providers))
            .map_err(|_| Error::Configuration(ConfigIssue::ApplePlatformSso))?,
        ))
    }
}
