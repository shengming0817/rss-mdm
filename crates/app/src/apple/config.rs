use crate::{ConfigIssue, Error, native::TlsEndpoint};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub management: TlsEndpoint,
    pub scep_url: String,
    pub scep_provisioner: String,
    pub issuer_certificate_file: PathBuf,
    pub profile_certificate_file: PathBuf,
    pub profile_private_key_file: PathBuf,
    pub apns_certificate_file: PathBuf,
    pub apns_private_key_file: PathBuf,
    pub apns_topic: String,
    pub challenge_webhook: Webhook,
    pub notify_webhook: Webhook,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub id: String,
    pub secret_file: PathBuf,
}
impl Webhook {
    fn valid(&self) -> bool {
        !self.id.is_empty()
            && self.id.len() <= 128
            && self
                .id
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-_".contains(&v))
    }
}
impl Config {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
        let bad = || Error::Configuration(ConfigIssue::Apple);
        let endpoint = crate::config::https_url(&self.management.origin).map_err(|_| bad())?;
        crate::config::https_url(&self.scep_url).map_err(|_| bad())?;
        if endpoint.origin().ascii_serialization() != self.management.origin
            || self.management.listen == browser
            || self.management.listen.port() == 0
            || !self.apns_topic.starts_with("com.apple.mgmt.")
            || self.apns_topic.len() > 255
            || !self.challenge_webhook.valid()
            || !self.notify_webhook.valid()
            || self.challenge_webhook.id == self.notify_webhook.id
            || self.scep_provisioner.is_empty()
            || self.scep_provisioner.len() > 128
        {
            return Err(bad());
        }
        Ok(())
    }
}
