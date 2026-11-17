use crate::{ConfigIssue, Error, native::PublicEndpoint};
use serde::Deserialize;
use std::net::SocketAddr;
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub management: PublicEndpoint,
    #[serde(default)]
    pub webhooks: Vec<crate::ca_webhooks::Credentials>,
}
impl Config {
    pub(crate) fn validate(&self, _browser: SocketAddr) -> Result<(), Error> {
        let endpoint = crate::config::https_url(&self.management.origin)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleListeners))?;
        if endpoint.origin().ascii_serialization() != self.management.origin {
            return Err(Error::Configuration(ConfigIssue::AppleListeners));
        }
        Ok(())
    }
}
