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
pub(super) enum Driver {
    Winget {
        base: String,
        artifacts_base: String,
    },
    Brew {
        base: String,
        artifacts_base: String,
        access: crate::BrewReadAccess,
        repo: brew::RepositoryScope,
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
pub(super) struct SourceResources {
    logical: String,
    config: SourceConfig,
    repository: Option<std::sync::Arc<brew::Repository>>,
    physical: String,
}
impl SourceResources {
    pub async fn new(logical: String, config: SourceConfig) -> Result<Self> {
        rss_mdm_resource::Id::new(&logical).map_err(|_| Error::Input)?;
        let (repository, physical) = match &config {
            SourceConfig::Winget(c) => (None, c.base.clone()),
            SourceConfig::Brew(c) => {
                let repository = brew::Repository::open(&c.repository, &c.tap)
                    .await
                    .map_err(|cause| Error::Source.context("config::compile", cause))?;
                let path = c.repository.canonicalize().map_err(|_| Error::Input)?;
                (
                    Some(std::sync::Arc::new(repository)),
                    path.to_str().ok_or(Error::Input)?.to_owned(),
                )
            }
        };
        Ok(Self {
            logical,
            config,
            repository,
            physical,
        })
    }
    /// Describe a tenant's target without acquiring execution credentials.
    pub fn target(&self, tenant: TenantId) -> Result<super::PublicTarget> {
        Ok(self.describe(tenant)?.0.target())
    }
    pub fn scope(&self, tenant: TenantId, credentials: &dyn crate::Credentials) -> Result<Sources> {
        let (source, configuration) = self.describe(tenant)?;
        let driver = match source.binding.protocol {
            ExportProtocol::Winget { base } => Driver::Winget {
                base,
                artifacts_base: source.artifacts_base,
            },
            ExportProtocol::Brew {
                base,
                tap,
                credential_reference,
            } => Driver::Brew {
                base,
                artifacts_base: source.artifacts_base,
                access: credentials.brew_read(tenant, &self.logical, &credential_reference)?,
                repo: self.repository.as_ref().ok_or(Error::Source)?.scope(tenant),
                tap,
                credential_reference,
            },
        };
        Ok(Sources {
            tenant,
            logical: source.logical,
            binding: Binding {
                identity: source.binding.identity,
                configuration,
                driver,
            },
            digest: source.digest,
        })
    }
    fn describe(&self, tenant: TenantId) -> Result<(ExportSources, Vec<u8>)> {
        rel::TargetId::new(tenant, &self.logical).map_err(|_| Error::Input)?;
        let address = |value: &str| -> Result<String> {
            let value =
                super::artifact::checked_url(&value.replace("{tenant}", &tenant.to_string()))?
                    .to_string();
            if !value.ends_with('/') {
                return Err(Error::Input);
            }
            Ok(value)
        };
        let (protocol, artifacts_base, configuration) = match &self.config {
            SourceConfig::Winget(c) => {
                let base = address(&c.base)?;
                let artifacts_base = address(&c.artifacts_base)?;
                let document = serde_json::json!([2, "hosted-winget", base, artifacts_base]);
                (ExportProtocol::Winget { base }, artifacts_base, document)
            }
            SourceConfig::Brew(c) => {
                let base = address(&c.base)?;
                let artifacts_base = address(&c.artifacts_base)?;
                let document = serde_json::json!([
                    2,
                    "brew",
                    self.physical,
                    c.tap,
                    base,
                    artifacts_base,
                    c.credential_reference
                ]);
                (
                    ExportProtocol::Brew {
                        base,
                        tap: c.tap.clone(),
                        credential_reference: c.credential_reference.clone(),
                    },
                    artifacts_base,
                    document,
                )
            }
        };
        let configuration = serde_json::to_vec(&serde_json::json!([
            1,
            tenant.to_string(),
            self.logical,
            configuration
        ]))
        .map_err(|_| Error::Input)?;
        let identity = Sha256::digest(
            serde_json::to_vec(&(tenant.to_string(), &self.physical)).map_err(|_| Error::Input)?,
        )
        .to_vec();
        let envelope = serde_json::to_vec(&serde_json::json!([
            1,
            tenant.to_string(),
            self.logical,
            identity,
            configuration
        ]))
        .map_err(|_| Error::Input)?;
        Ok((
            ExportSources {
                tenant,
                logical: self.logical.clone(),
                digest: Sha256::digest(envelope).into(),
                binding: ExportBinding { identity, protocol },
                artifacts_base,
            },
            configuration,
        ))
    }
}
impl Sources {
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
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
    pub(super) fn target(&self) -> super::PublicTarget {
        super::PublicTarget {
            id: self.logical.clone(),
            digest: self.digest,
            protocol: match self.binding.protocol {
                ExportProtocol::Winget { .. } => super::TargetProtocol::Winget,
                ExportProtocol::Brew { .. } => super::TargetProtocol::Brew,
            },
        }
    }
    pub(super) fn binding(&self) -> &ExportBinding {
        &self.binding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Unavailable;
    impl crate::Credentials for Unavailable {
        fn brew_read(&self, _: TenantId, _: &str, _: &str) -> Result<crate::BrewReadAccess> {
            Err(Error::Identity)
        }
    }
    #[test]
    fn target_metadata_is_tenant_bound_without_execution_credentials() {
        let a = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let b = TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
        let source = SourceResources {
            logical: "enterprise".into(),
            config: SourceConfig::Winget(WingetConfig {
                base: "https://mdm.example/{tenant}/winget/".into(),
                artifacts_base: "https://mdm.example/{tenant}/artifacts/".into(),
            }),
            repository: None,
            physical: "https://mdm.example/{tenant}/winget/".into(),
        };
        assert_eq!(
            source.target(a).unwrap().digest,
            source.scope(a, &Unavailable).unwrap().digest
        );
        assert_ne!(
            source.target(a).unwrap().digest,
            source.target(b).unwrap().digest
        );
        let brew = SourceResources {
            config: SourceConfig::Brew(BrewConfig {
                base: "https://mdm.example/{tenant}/brew/".into(),
                artifacts_base: "https://mdm.example/{tenant}/artifacts/".into(),
                credential_reference: "read".into(),
                tap: "enterprise/software".into(),
                repository: "/unused".into(),
            }),
            ..source
        };
        assert!(matches!(
            brew.target(b).unwrap().protocol,
            super::super::TargetProtocol::Brew
        ));
        assert!(matches!(brew.scope(b, &Unavailable), Err(Error::Identity)));
    }
}
