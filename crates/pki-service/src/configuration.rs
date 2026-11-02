//! Host-selected provider material; provider execution remains in the PKI owner.
use crate::Error;
use rss_mdm_agent_wire::pki::{Purpose, Trust};
use rss_mdm_device_trust::DeviceTrust;
pub fn load(path: &std::path::Path, purpose: Purpose, now: i64) -> Result<DeviceTrust, Error> {
    let bytes = rss_mdm_install_support::files::read(path, 64 * 1024 * 1024, false)
        .map_err(|_| Error::Configuration)?;
    decode(&bytes, purpose, now)
}
pub fn decode(bytes: &[u8], purpose: Purpose, now: i64) -> Result<DeviceTrust, Error> {
    let trust: Trust = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
    DeviceTrust::restore(trust, purpose, now).map_err(|_| Error::Configuration)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(default)]
    pub scep_url: Option<String>,
    pub purpose: Purpose,
    pub issuer: String,
    pub origin: String,
    pub tls_root_file: std::path::PathBuf,
    pub provisioner: String,
    pub kid: String,
    pub provisioner_key_file: std::path::PathBuf,
}
pub fn providers(
    config: &[Provider],
) -> Result<std::sync::Arc<crate::providers::Providers>, Error> {
    let entries = config
        .iter()
        .map(|p| {
            let invalid = || Error::Configuration;
            let client = crate::StepCa::new(
                crate::Configuration {
                    origin: p.origin.clone(),
                    provisioner: p.provisioner.clone(),
                    kid: p.kid.clone(),
                },
                &rss_mdm_install_support::files::read(&p.tls_root_file, 131072, false)
                    .map_err(|_| invalid())?,
                &rss_mdm_install_support::files::read(&p.provisioner_key_file, 32768, true)
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
            Ok(crate::providers::Provider {
                purpose: p.purpose,
                issuer: p.issuer.clone(),
                client: std::sync::Arc::new(client),
                scep_url: p.scep_url.clone(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    crate::providers::Providers::new(entries)
        .map(std::sync::Arc::new)
        .map_err(|_| Error::Configuration)
}
