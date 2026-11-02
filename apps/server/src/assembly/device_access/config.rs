use crate::{ConfigIssue, Error};
use serde::Deserialize;
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: crate::config::Database,
    pub deployment_authorities: Vec<DeploymentAuthority>,
    pub platform_sso: Option<PlatformSso>,
    pub registration: Option<Registration>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub listen: std::net::SocketAddr,
    pub origin: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_file: PathBuf,
    pub providers: Vec<crate::device_pki::Provider>,
    pub certificate_days: u16,
    pub configuration_revision: Option<u64>,
    pub configuration_lifetime: std::num::NonZeroU32,
}
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAuthority {
    pub id: uuid::Uuid,
    pub public_key: [u8; 32],
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
    pub configuration:
        rss_mdm_device_access_postgres::platform_sso::password_provider::Configuration,
    pub client_secret_file: PathBuf,
    pub private_ca_file: Option<PathBuf>,
}
impl PlatformSso {
    pub(crate) fn load(
        &self,
        origin: &str,
        tenant: rss_request_context::TenantId,
        authorities: &rss_mdm_device_access_postgres::evidence::Authorities,
    ) -> Result<std::sync::Arc<rss_mdm_device_access_postgres::platform_sso::Runtime>, Error> {
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
                rss_mdm_device_access_postgres::platform_sso::crypto::Signer::from_pem(&bytes)
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
                rss_mdm_device_access_postgres::platform_sso::password_provider::Provider::new(
                    config.configuration.clone(),
                    secret,
                    ca.as_deref().map(|v| v.as_slice()),
                )
                .map_err(|_| Error::Configuration(ConfigIssue::ApplePlatformSso))?,
            );
        }
        Ok(std::sync::Arc::new(
            rss_mdm_device_access_postgres::platform_sso::Runtime::new(
                self.configuration.clone(),
                origin,
                tenant,
                self.active_key.clone(),
                keys,
            )
            .and_then(|runtime| runtime.with_password_providers(providers))
            .map(|mut runtime| {
                runtime.evidence = authorities.clone();
                runtime
            })
            .map_err(|_| Error::Configuration(ConfigIssue::ApplePlatformSso))?,
        ))
    }
}
