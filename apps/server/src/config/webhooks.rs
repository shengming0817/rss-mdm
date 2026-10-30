use rss_mdm_webhook_service::{
    Error,
    network::{Network as LoadedNetwork, Policies},
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
use uuid::Uuid;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub networks: Vec<Network>,
    pub recovery_database: crate::config::Database,
}
#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub tenant: Uuid,
    pub reference: String,
    pub hostname: String,
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
    pub cidrs: Vec<ipnet::IpNet>,
    pub ca_files: Vec<PathBuf>,
}

impl Config {
    pub(crate) fn material_configuration(&self) -> Result<String, Error> {
        Ok(self.compile()?.digest().to_owned())
    }
    pub(crate) fn compile(&self) -> Result<Policies, Error> {
        use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut networks = Vec::new();
        for network in &self.networks {
            if network.ca_files.len() > 16 {
                return Err(Error::Invalid);
            }
            let mut roots = Vec::new();
            for path in &network.ca_files {
                let bytes =
                    crate::config::read(path, 1024 * 1024, false).map_err(|_| Error::Invalid)?;
                for cert in CertificateDer::pem_slice_iter(&bytes) {
                    roots.push(cert.map_err(|_| Error::Invalid)?.to_vec());
                }
            }
            networks.push(LoadedNetwork {
                tenant: network.tenant,
                reference: network.reference.clone(),
                hostname: network.hostname.clone(),
                port: network.port,
                addresses: network.addresses.clone(),
                cidrs: network.cidrs.clone(),
                roots,
            });
        }
        Policies::compile(networks)
    }
}
