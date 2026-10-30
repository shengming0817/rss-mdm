use super::*;
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};
use webhooks::transport::{AuthorizedTarget, NetworkAccess, SigningKey, SigningKeys, TrustRoots};
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
pub(super) struct Policies {
    configuration: String,
    networks: BTreeMap<(Uuid, String), Network>,
    roots: BTreeMap<(Uuid, String), TrustRoots>,
}
impl Config {
    pub(crate) fn material_configuration(&self) -> Result<String, HttpError> {
        self.clone().compile().map(|p| p.configuration)
    }

    pub(super) fn compile(self) -> Result<Policies, HttpError> {
        use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut identities = BTreeMap::new();
        let mut networks = BTreeMap::new();
        let mut roots = BTreeMap::new();
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
            use sha2::{Digest, Sha256};
            let mut fingerprints = certificates
                .iter()
                .map(|c| format!("{:x}", Sha256::digest(c)))
                .collect::<Vec<_>>();
            fingerprints.sort();
            fingerprints.dedup();
            let mut addresses = network.addresses.clone();
            addresses.sort();
            addresses.dedup();
            let mut cidrs = network
                .cidrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            cidrs.sort();
            cidrs.dedup();
            identities.insert((network.tenant,network.reference.clone()),serde_json::json!({"hostname":network.hostname,"port":network.port,"addresses":addresses,"cidrs":cidrs,"roots":fingerprints}));
            let trust = TrustRoots::from_der(certificates).map_err(|_| HttpError::Malformed)?;
            let key = (network.tenant, network.reference.clone());
            if roots.insert(key.clone(), trust).is_some() || networks.insert(key, network).is_some()
            {
                return Err(HttpError::Malformed);
            }
        }
        use sha2::{Digest, Sha256};
        let configuration = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&identities.into_iter().collect::<Vec<_>>())
                    .map_err(|_| HttpError::Malformed)?
            )
        );
        Ok(Policies {
            configuration,
            networks,
            roots,
        })
    }
}
impl Policies {
    pub(super) fn digest(&self) -> &str {
        &self.configuration
    }

    pub(super) fn check_material(
        &self,
        tenant: Uuid,
        reference: &str,
        endpoint: &str,
    ) -> Result<(), HttpError> {
        let network = self
            .networks
            .get(&(tenant, reference.to_owned()))
            .ok_or(HttpError::Forbidden)?;
        let url = url::Url::parse(endpoint).map_err(|_| HttpError::Malformed)?;
        if url.scheme() != "https"
            || url.host_str() != Some(network.hostname.as_str())
            || url.port_or_known_default() != Some(network.port)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
        {
            return Err(HttpError::Forbidden);
        }
        Ok(())
    }
    pub(super) fn check(&self, t: Uuid, settings: &Settings) -> Result<(), HttpError> {
        let network = self
            .networks
            .get(&(t, settings.network_reference.clone()))
            .ok_or(HttpError::Forbidden)?;
        let url = url::Url::parse(&settings.endpoint).map_err(|_| HttpError::Malformed)?;
        if url.host_str() != Some(network.hostname.as_str())
            || url.port_or_known_default() != Some(network.port)
        {
            return Err(HttpError::Forbidden);
        }
        settings.validate().map_err(map_error)
    }
    pub(super) async fn target(
        &self,
        c: &mut PgConnection,
        protection: &rss_mdm_native_protection::Protector,
        t: Uuid,
        subscription: &Subscription,
        now: i64,
    ) -> Result<AuthorizedTarget, webhooks::Error> {
        self.check(t, &subscription.settings)
            .map_err(|_| webhooks::Error::Denied)?;
        let netkey = (t, subscription.settings.network_reference.clone());
        let network = self.networks.get(&netkey).ok_or(webhooks::Error::Denied)?;
        let material = webhooks::materials::load(
            c,
            t,
            &subscription.settings.key_reference,
            &self.configuration,
            protection,
        )
        .await?;
        let current =
            SigningKey::from_encoded(&material.current).map_err(|_| webhooks::Error::Storage)?;
        let retiring = material
            .retiring
            .as_ref()
            .map(|key| SigningKey::from_encoded(key).map_err(|_| webhooks::Error::Storage))
            .transpose()?;
        let _ = now;
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
