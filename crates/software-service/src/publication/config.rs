use super::{Error, Result};
use rss_mdm_brew_source as brew;
use rss_mdm_software_release as rel;
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WingetConfig {
    pub base: String,
    pub artifacts_base: String,
}
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrewConfig {
    pub base: String,
    pub artifacts_base: String,
    pub credential_reference: String,
    pub tap: String,
    pub repository: PathBuf,
}
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SourceConfig {
    Winget(WingetConfig),
    Brew(BrewConfig),
}
/// Fixed, named publication environments; each must own a distinct physical source.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
pub struct ServiceIdentity {
    pub backend: rel::ActorId,
}
impl ServiceIdentity {
    pub(super) fn check(&self, t: TenantId) -> Result<()> {
        if self.backend.tenant() != t {
            return Err(Error::Identity);
        }
        Ok(())
    }
}
pub(super) enum Driver {
    Winget {
        base: String,
        artifacts_base: String,
    },
    Brew {
        base: String,
        artifacts_base: String,
        access: crate::BrewReadAccess,
        repo: brew::Repository,
        tap: String,
        credential_reference: String,
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
    pub async fn new(
        tenant: TenantId,
        logical: String,
        config: RingSources,
        credentials: &dyn crate::Credentials,
    ) -> Result<Self> {
        rel::SoftwareIdentity::new(rel::SoftwareIdentityFields {
            source: logical.clone(),
            package: "validation".into(),
            version: "1".into(),
            platform: "validation".into(),
        })
        .map_err(|cause| Error::Input.context("config::new", cause))?;
        let mut values = Vec::new();
        for (ring, config) in config.ordered().into_iter().enumerate() {
            let mut binding = compile(tenant, &logical, config, credentials).await?;
            binding.configuration = serde_json::to_vec(&serde_json::json!([
                1,
                logical,
                ring,
                binding.configuration
            ]))
            .map_err(|cause| Error::Input.context("config::new", cause))?;
            values.push(binding);
        }
        if values
            .iter()
            .any(|b| std::mem::discriminant(&b.driver) != std::mem::discriminant(&values[0].driver))
        {
            return Err(Error::Input);
        }
        let artifact_base = |b: &Binding| match &b.driver {
            Driver::Winget { artifacts_base, .. } | Driver::Brew { artifacts_base, .. } => {
                artifacts_base.clone()
            }
        };
        if values
            .iter()
            .any(|b| artifact_base(b) != artifact_base(&values[0]))
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
        .map_err(|cause| Error::Input.context("config::new", cause))?;
        let digest = Sha256::digest(envelope).into();
        let bindings = values
            .try_into()
            .map_err(|cause| Error::Input.context("config::new", cause))?;
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
async fn compile(
    tenant: TenantId,
    logical: &str,
    config: SourceConfig,
    credentials: &dyn crate::Credentials,
) -> Result<Binding> {
    let (driver, physical, configuration) = match config {
        SourceConfig::Winget(c) => {
            let physical = super::artifact::checked_url(&c.base)?.to_string();
            let artifacts_base = super::artifact::checked_url(&c.artifacts_base)?.to_string();
            if !physical.ends_with('/') || !artifacts_base.ends_with('/') {
                return Err(Error::Input);
            }
            let configuration = serde_json::to_vec(&serde_json::json!([
                2,
                "hosted-winget",
                physical,
                artifacts_base
            ]))
            .map_err(|_| Error::Input)?;
            (
                Driver::Winget {
                    base: physical.clone(),
                    artifacts_base,
                },
                physical,
                configuration,
            )
        }

        SourceConfig::Brew(c) => {
            let path = c
                .repository
                .canonicalize()
                .map_err(|cause| Error::Input.context("config::compile", cause))?;
            let physical = path.to_str().ok_or(Error::Input)?.to_owned();
            let repo = brew::Repository::open(&path, tenant, &c.tap)
                .await
                .map_err(|cause| Error::Source.context("config::compile", cause))?;
            let base = super::artifact::checked_url(&c.base)?.to_string();
            let artifacts_base = super::artifact::checked_url(&c.artifacts_base)?.to_string();
            if !base.ends_with('/') || !artifacts_base.ends_with('/') {
                return Err(Error::Input);
            }
            let access = credentials.brew_read(tenant, logical, &c.credential_reference)?;
            let configuration = serde_json::to_vec(&serde_json::json!([
                2,
                "brew",
                physical,
                c.tap,
                base,
                artifacts_base,
                c.credential_reference
            ]))
            .map_err(|cause| Error::Input.context("config::compile", cause))?;
            (
                Driver::Brew {
                    repo,
                    tap: c.tap,
                    base,
                    artifacts_base,
                    access,
                    credential_reference: c.credential_reference,
                },
                physical,
                configuration,
            )
        }
    };
    Ok(Binding {
        identity: Sha256::digest(physical.as_bytes()).to_vec(),
        configuration,
        physical,
        driver,
    })
}

/// Frozen non-secret projection of an already validated source binding.
#[derive(Clone)]
pub(super) enum ExportProtocol {
    Winget {
        base: String,
    },
    Brew {
        base: String,
        tap: String,
        credential_reference: String,
    },
}
#[derive(Clone)]
pub(super) struct ExportBinding {
    pub identity: Vec<u8>,
    pub protocol: ExportProtocol,
}
#[derive(Clone)]
pub(super) struct ExportSources {
    pub tenant: TenantId,
    pub logical: String,
    pub digest: [u8; 32],
    pub bindings: [ExportBinding; 3],
    pub artifacts_base: String,
}
impl Sources {
    pub(super) fn exports(&self) -> ExportSources {
        ExportSources {
            tenant: self.tenant,
            logical: self.logical.clone(),
            digest: self.digest,
            artifacts_base: match &self.bindings[0].driver {
                Driver::Winget { artifacts_base, .. } | Driver::Brew { artifacts_base, .. } => {
                    artifacts_base.clone()
                }
            },
            bindings: std::array::from_fn(|i| {
                let binding = &self.bindings[i];
                ExportBinding {
                    identity: binding.identity.clone(),
                    protocol: match &binding.driver {
                        Driver::Winget { base, .. } => {
                            ExportProtocol::Winget { base: base.clone() }
                        }
                        Driver::Brew {
                            base,
                            tap,
                            credential_reference,
                            ..
                        } => ExportProtocol::Brew {
                            base: base.clone(),
                            tap: tap.clone(),
                            credential_reference: credential_reference.clone(),
                        },
                    },
                }
            }),
        }
    }
}
impl ExportSources {
    pub(super) fn binding(&self, ring: rel::Ring) -> &ExportBinding {
        &self.bindings[index(ring)]
    }
}
