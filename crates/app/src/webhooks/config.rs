use super::*;
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};
use webhooks::transport::{AuthorizedTarget, NetworkAccess, SigningKey, SigningKeys, TrustRoots};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub keys: Vec<Key>,
    pub networks: Vec<Network>,
    pub recovery_database: crate::config::Database,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub tenant: Uuid,
    pub reference: String,
    pub version: u64,
    pub current_file: PathBuf,
    pub retiring: Option<Retiring>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retiring {
    pub version: u64,
    pub key_file: PathBuf,
    pub until: i64,
}
#[derive(Deserialize)]
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
struct Material {
    current: zeroize::Zeroizing<String>,
    retiring: Option<(zeroize::Zeroizing<String>, i64)>,
}
pub(super) struct Policies {
    keys: BTreeMap<(Uuid, String), Material>,
    networks: BTreeMap<(Uuid, String), Network>,
    roots: BTreeMap<(Uuid, String), TrustRoots>,
}
impl Config {
    pub(super) fn compile(self) -> Result<Policies, HttpError> {
        use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut keys = BTreeMap::new();
        let mut networks = BTreeMap::new();
        let mut roots = BTreeMap::new();
        for key in self.keys {
            if key.tenant.is_nil() || key.reference.is_empty() || key.version == 0 {
                return Err(HttpError::Malformed);
            }
            let current =
                crate::config::secret(&key.current_file).map_err(|_| HttpError::Malformed)?;
            SigningKey::from_encoded(&current).map_err(|_| HttpError::Malformed)?;
            let retiring = key
                .retiring
                .map(|v| {
                    if v.version == 0 || v.version >= key.version || v.until < 0 {
                        return Err(HttpError::Malformed);
                    }
                    let secret =
                        crate::config::secret(&v.key_file).map_err(|_| HttpError::Malformed)?;
                    SigningKey::from_encoded(&secret).map_err(|_| HttpError::Malformed)?;
                    Ok((secret, v.until))
                })
                .transpose()?;
            if keys
                .insert((key.tenant, key.reference), Material { current, retiring })
                .is_some()
            {
                return Err(HttpError::Malformed);
            }
        }
        for network in self.networks {
            if network.tenant.is_nil()
                || network.reference.is_empty()
                || network.hostname.is_empty()
                || network.port == 0
                || network.addresses.iter().any(|a| a.port() != network.port)
                || network.addresses.len() > 16
                || network.ca_files.len() > 16
            {
                return Err(HttpError::Malformed);
            }
            NetworkAccess::new(network.addresses.clone(), network.cidrs.clone())
                .map_err(|_| HttpError::Malformed)?;
            let mut certificates = Vec::new();
            for path in &network.ca_files {
                let bytes = crate::config::read(path, 1024 * 1024, false)
                    .map_err(|_| HttpError::Malformed)?;
                for cert in CertificateDer::pem_slice_iter(&bytes) {
                    certificates.push(cert.map_err(|_| HttpError::Malformed)?.to_vec());
                }
            }
            let trust = TrustRoots::from_der(certificates).map_err(|_| HttpError::Malformed)?;
            let key = (network.tenant, network.reference.clone());
            if roots.insert(key.clone(), trust).is_some() || networks.insert(key, network).is_some()
            {
                return Err(HttpError::Malformed);
            }
        }
        Ok(Policies {
            keys,
            networks,
            roots,
        })
    }
}
impl Policies {
    pub(super) fn check(&self, t: Uuid, settings: &Settings) -> Result<(), HttpError> {
        let network = self
            .networks
            .get(&(t, settings.network_reference.clone()))
            .ok_or(HttpError::Forbidden)?;
        let url = url::Url::parse(&settings.endpoint).map_err(|_| HttpError::Malformed)?;
        if !self.keys.contains_key(&(t, settings.key_reference.clone()))
            || url.host_str() != Some(network.hostname.as_str())
            || url.port_or_known_default() != Some(network.port)
        {
            return Err(HttpError::Forbidden);
        }
        settings.validate().map_err(map_error)
    }
    pub(super) fn target(
        &self,
        t: Uuid,
        subscription: &Subscription,
        now: i64,
    ) -> Result<AuthorizedTarget, webhooks::Error> {
        self.check(t, &subscription.settings)
            .map_err(|_| webhooks::Error::Denied)?;
        let netkey = (t, subscription.settings.network_reference.clone());
        let network = self.networks.get(&netkey).ok_or(webhooks::Error::Denied)?;
        let material = self
            .keys
            .get(&(t, subscription.settings.key_reference.clone()))
            .ok_or(webhooks::Error::Denied)?;
        let current =
            SigningKey::from_encoded(&material.current).map_err(|_| webhooks::Error::Storage)?;
        let retiring = material
            .retiring
            .as_ref()
            .filter(|(_, until)| now < *until)
            .map(|(secret, _)| {
                SigningKey::from_encoded(secret).map_err(|_| webhooks::Error::Storage)
            })
            .transpose()?;
        let target = webhooks::transport::Target::new(
            webhooks::transport::TargetId::parse(&subscription.id.to_string())
                .map_err(|_| webhooks::Error::Invalid)?,
            webhooks::transport::TargetVersion::new(
                subscription
                    .target_version
                    .try_into()
                    .map_err(|_| webhooks::Error::Invalid)?,
            )
            .map_err(|_| webhooks::Error::Invalid)?,
        );
        AuthorizedTarget::new(
            TenantId::parse(&t.to_string()).map_err(|_| webhooks::Error::Invalid)?,
            target,
            &subscription.settings.endpoint,
            NetworkAccess::new(network.addresses.clone(), network.cidrs.clone())
                .map_err(|_| webhooks::Error::Storage)?,
            self.roots
                .get(&netkey)
                .ok_or(webhooks::Error::Storage)?
                .clone(),
            SigningKeys::new(current, retiring),
        )
        .map_err(|_| webhooks::Error::Storage)
    }
}
