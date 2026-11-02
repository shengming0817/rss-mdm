use crate::Error;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformSso {
    pub configuration: rss_mdm_agent_wire::platform_sso::Configuration,
    pub active_key: String,
    pub signing_keys: std::collections::BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub password_providers: Vec<PasswordProvider>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordProvider {
    pub configuration:
        rss_mdm_device_access_postgres::platform_sso::password_provider::Configuration,
    pub client_secret_file: PathBuf,
    pub private_ca_file: Option<PathBuf>,
}
impl PlatformSso {
    pub fn load(
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
                return Err(Error::Configuration);
            }
            let bytes = rss_mdm_install_support::files::read(path, 16384, true)
                .map_err(|_| Error::Configuration)?;
            keys.insert(
                name.clone(),
                rss_mdm_device_access_postgres::platform_sso::crypto::Signer::from_pem(&bytes)
                    .map_err(|_| Error::Configuration)?,
            );
        }
        let tenant =
            uuid::Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Configuration)?;
        let mut providers = Vec::new();
        for config in &self.password_providers {
            let bytes =
                rss_mdm_install_support::files::read(&config.client_secret_file, 4096, true)
                    .map_err(|_| Error::Configuration)?;
            let secret = zeroize::Zeroizing::new(
                std::str::from_utf8(&bytes)
                    .map_err(|_| Error::Configuration)?
                    .trim_end()
                    .to_owned(),
            );
            let ca = config
                .private_ca_file
                .as_ref()
                .map(|path| rss_mdm_install_support::files::read(path, 65536, false))
                .transpose()
                .map_err(|_| Error::Configuration)?;
            providers.push(
                rss_mdm_device_access_postgres::platform_sso::password_provider::Provider::new(
                    config.configuration.clone(),
                    secret,
                    ca.as_deref().map(|v| v.as_slice()),
                )
                .map_err(|_| Error::Configuration)?,
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
            .map_err(|_| Error::Configuration)?,
        ))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAuthority {
    pub id: uuid::Uuid,
    pub public_key: [u8; 32],
}
