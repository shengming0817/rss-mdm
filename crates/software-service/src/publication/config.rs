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
    pub driver: Driver,
}
pub(super) struct Sources {
    pub tenant: TenantId,
    pub logical: String,
    pub binding: Binding,
    pub digest: [u8; 32],
}
impl Sources {
    pub async fn new(
        tenant: TenantId,
        logical: String,
        config: SourceConfig,
        credentials: &dyn crate::Credentials,
    ) -> Result<Self> {
        rel::TargetId::new(tenant, &logical).map_err(|_| Error::Input)?;
        let mut binding = compile(tenant, &logical, config, credentials).await?;
        binding.configuration = serde_json::to_vec(&serde_json::json!([
            1,
            tenant.to_string(),
            logical,
            binding.configuration
        ]))
        .map_err(|_| Error::Input)?;
        let envelope = serde_json::to_vec(&serde_json::json!([
            1,
            tenant.to_string(),
            logical,
            binding.identity,
            binding.configuration
        ]))
        .map_err(|_| Error::Input)?;
        let digest = Sha256::digest(envelope).into();
        Ok(Self {
            tenant,
            logical,
            binding,
            digest,
        })
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
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
    pub binding: ExportBinding,
    pub artifacts_base: String,
}
impl Sources {
    pub(super) fn exports(&self) -> ExportSources {
        let b = &self.binding;
        ExportSources {
            tenant: self.tenant,
            logical: self.logical.clone(),
            digest: self.digest,
            artifacts_base: match &b.driver {
                Driver::Winget { artifacts_base, .. } | Driver::Brew { artifacts_base, .. } => {
                    artifacts_base.clone()
                }
            },
            binding: ExportBinding {
                identity: b.identity.clone(),
                protocol: match &b.driver {
                    Driver::Winget { base, .. } => ExportProtocol::Winget { base: base.clone() },
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
            },
        }
    }
}
impl ExportSources {
    pub(super) fn binding(&self) -> &ExportBinding {
        &self.binding
    }
}
