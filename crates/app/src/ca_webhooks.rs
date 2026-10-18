//! Deployment-owned CA callback credentials; issuer identity never comes from request JSON.
use crate::{ConfigIssue, Error};
use serde::Deserialize;
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub id: String,
    pub secret_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub issuer: String,
    pub challenge: Webhook,
    pub notify: Webhook,
}
pub(crate) fn load(
    inputs: &[Credentials],
    trust: &rss_mdm_device_trust::DeviceTrust,
) -> Result<rss_mdm_pki_service::scep::Verifier, Error> {
    let invalid = || Error::Configuration(ConfigIssue::SecretContents);
    let public = trust.public().map_err(|_| invalid())?;
    if inputs.len() != public.issuers.len() {
        return Err(invalid());
    }
    let mut credentials = Vec::new();
    for input in inputs {
        if !public.issuers.iter().any(|g| g.digest == input.issuer) {
            return Err(invalid());
        }
        let read = |v: &Webhook, issue| {
            let bytes = crate::config::read(&v.secret_file, 4096, true)
                .map_err(|_| Error::Configuration(issue))?;
            rss_mdm_pki_service::scep::key(&bytes).map_err(|_| Error::Configuration(issue))
        };
        credentials.push(rss_mdm_pki_service::scep::Credentials {
            issuer: input.issuer.clone(),
            challenge_id: input.challenge.id.clone(),
            challenge_key: read(&input.challenge, ConfigIssue::AppleChallengeWebhook)?,
            notify_id: input.notify.id.clone(),
            notify_key: read(&input.notify, ConfigIssue::AppleNotifyWebhook)?,
        });
    }
    rss_mdm_pki_service::scep::Verifier::new(credentials).map_err(|_| invalid())
}
