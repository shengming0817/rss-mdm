use serde::Deserialize;
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub reports: rss_mdm_device_access_postgres::reports::Limits,
    pub database: crate::config::Database,
    pub deployment_authorities: Vec<DeploymentAuthority>,
    pub platform_sso: Option<rss_mdm_device_access_runtime::platform::PlatformSso>,
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
    pub providers: Vec<rss_mdm_pki_service::configuration::Provider>,
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
