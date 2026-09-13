use super::{Error, Result};
use rss_mdm_brew_source as brew;
use rss_mdm_software_release as rel;
use rss_mdm_winget_source as winget;
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use std::{net::IpAddr, path::PathBuf};
#[derive(Clone)]
pub struct WingetConfig {
    pub base: String,
    pub addresses: Vec<IpAddr>,
    pub private_ca: Option<Vec<u8>>,
    pub credential_reference: String,
    pub credential_file: PathBuf,
}
#[derive(Clone)]
pub struct BrewConfig {
    pub tap: String,
    pub repository: PathBuf,
}
#[derive(Clone)]
pub enum SourceConfig {
    Winget(WingetConfig),
    Brew(BrewConfig),
}
/// Fixed, named publication environments; each must own a distinct physical source.
#[derive(Clone)]
pub struct RingSources {
    pub test: SourceConfig,
    pub pilot: SourceConfig,
    pub production: SourceConfig,
}
impl RingSources {
    fn ordered(self) -> [SourceConfig; 3] {
        [self.test, self.pilot, self.production]
    }
}
/// Identities are attested by this controlled process, never by an HTTP request body.
pub struct ServiceActors {
    pub validator: rel::ActorId,
    pub approver: rel::ActorId,
    pub publisher: rel::ActorId,
    pub backend: rel::ActorId,
}
impl ServiceActors {
    pub(super) fn check(&self, t: TenantId) -> Result<()> {
        if [
            &self.validator,
            &self.approver,
            &self.publisher,
            &self.backend,
        ]
        .iter()
        .any(|a| a.tenant() != t)
            || self.approver == self.publisher
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
}
pub(super) enum Driver {
    Winget {
        publisher: Box<winget::Publisher>,
        access: winget::WriteAccess,
    },
    Brew {
        repo: brew::Repository,
        tap: String,
    },
}
pub(super) struct Binding {
    pub identity: Vec<u8>,
    pub configuration: Vec<u8>,
    pub physical: String,
    pub driver: Driver,
}
pub(super) struct Sources {
    pub tenant: TenantId,
    pub logical: String,
    pub bindings: [Binding; 3],
    pub digest: [u8; 32],
}
impl Sources {
    pub async fn new(tenant: TenantId, logical: String, config: RingSources) -> Result<Self> {
        rel::SoftwareIdentity::new(rel::SoftwareIdentityFields {
            source: logical.clone(),
            package: "validation".into(),
            version: "1".into(),
            platform: "validation".into(),
        })
        .map_err(|_| Error::Input)?;
        let mut values = Vec::new();
        for (ring, config) in config.ordered().into_iter().enumerate() {
            let mut binding = compile(tenant, &logical, config).await?;
            binding.configuration = serde_json::to_vec(&serde_json::json!([
                1,
                logical,
                ring,
                binding.configuration
            ]))
            .map_err(|_| Error::Input)?;
            values.push(binding);
        }
        if values
            .iter()
            .any(|b| std::mem::discriminant(&b.driver) != std::mem::discriminant(&values[0].driver))
        {
            return Err(Error::Input);
        }
        let mut seen = std::collections::BTreeSet::new();
        if values.iter().any(|v| !seen.insert(&v.physical)) {
            return Err(Error::Identity);
        }
        let envelope = serde_json::to_vec(&serde_json::json!([
            1,
            tenant.to_string(),
            logical,
            values
                .iter()
                .map(|b| (&b.identity, &b.configuration))
                .collect::<Vec<_>>()
        ]))
        .map_err(|_| Error::Input)?;
        let digest = Sha256::digest(envelope).into();
        let bindings = values.try_into().map_err(|_| Error::Input)?;
        Ok(Self {
            tenant,
            logical,
            bindings,
            digest,
        })
    }
    pub fn binding(&self, ring: rel::Ring) -> &Binding {
        &self.bindings[index(ring)]
    }
}
pub(super) fn index(r: rel::Ring) -> usize {
    match r {
        rel::Ring::Test => 0,
        rel::Ring::Pilot => 1,
        rel::Ring::Production => 2,
    }
}
async fn compile(tenant: TenantId, logical: &str, config: SourceConfig) -> Result<Binding> {
    let (driver, physical, configuration) = match config {
        SourceConfig::Winget(c) => {
            let physical = super::artifact::checked_url(&c.base)?.to_string();
            let mut source = winget::Source::new(
                tenant,
                logical,
                &c.base,
                c.addresses.clone(),
                &c.credential_reference,
            )
            .map_err(|_| Error::Input)?;
            if let Some(ca) = &c.private_ca {
                source = source.with_root_certificate(ca).map_err(|_| Error::Input)?;
            }
            let token = crate::config::secret(&c.credential_file).map_err(|_| Error::Identity)?;
            let access = winget::WriteAccess::new(tenant, logical, &c.credential_reference, &token)
                .map_err(|_| Error::Identity)?;
            let configuration = serde_json::to_vec(&serde_json::json!([
                1,
                "winget",
                physical,
                c.addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                c.private_ca.as_ref().map(|b| Sha256::digest(b).to_vec()),
                c.credential_reference
            ]))
            .map_err(|_| Error::Input)?;
            (
                Driver::Winget {
                    publisher: Box::new(winget::Publisher::new(source).map_err(|_| Error::Input)?),
                    access,
                },
                physical,
                configuration,
            )
        }
        SourceConfig::Brew(c) => {
            let path = c.repository.canonicalize().map_err(|_| Error::Input)?;
            let physical = path.to_str().ok_or(Error::Input)?.to_owned();
            let repo = brew::Repository::open(&path, tenant, &c.tap)
                .await
                .map_err(|_| Error::Source)?;
            let configuration =
                serde_json::to_vec(&serde_json::json!([1, "brew", physical, c.tap]))
                    .map_err(|_| Error::Input)?;
            (Driver::Brew { repo, tap: c.tap }, physical, configuration)
        }
    };
    Ok(Binding {
        identity: Sha256::digest(physical.as_bytes()).to_vec(),
        configuration,
        physical,
        driver,
    })
}
