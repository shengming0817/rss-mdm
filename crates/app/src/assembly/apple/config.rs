use crate::{ConfigIssue, Error, native::TlsEndpoint};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[cfg(test)]
    #[serde(skip)]
    pub test_push_transport: Option<(String, PathBuf)>,
    pub management: TlsEndpoint,
    #[serde(default)]
    pub trust_file: PathBuf,
    pub materials: rss_mdm_apple_channel::runtime_materials::runtime::Selection,
    #[serde(default = "unconfigured_seed")]
    pub identity_seed: rss_mdm_apple_channel::IdentitySeed,
    #[serde(default)]
    pub webhooks: Vec<crate::ca_webhooks::Credentials>,
}
impl Config {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
        let bad = |issue| Error::Configuration(issue);
        let endpoint = crate::config::https_url(&self.management.origin)
            .map_err(|_| bad(ConfigIssue::AppleListeners))?;
        if endpoint.origin().ascii_serialization() != self.management.origin
            || self.management.listen == browser
            || self.management.listen.port() == 0
        {
            return Err(bad(ConfigIssue::AppleListeners));
        }
        if self.materials.apns < 1
            || self.materials.profile < 1
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
        if !valid(&self.identity_seed.challenge_id)
            || !valid(&self.identity_seed.notify_id)
            || self.identity_seed.challenge_id == self.identity_seed.notify_id
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
