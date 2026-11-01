//! Native software is a projection of approved Resource material, never an Agent bootstrap.
use crate::catalog::Error;
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Msi {
        product: Uuid,
        version: String,
    },
    Msix {
        family: String,
        identity: r::MsixIdentity,
    },
    Pkg {
        receipt: String,
        version: String,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub identity: Identity,
    pub artifact: r::SoftwareArtifact,
    pub origin: String,
    pub timeout_seconds: u32,
    pub minimum_os: Option<[u16; 4]>,
}
impl Package {
    pub fn compile(
        definition: &r::SoftwareDefinition,
        origin: String,
    ) -> std::result::Result<Self, Error> {
        let spec = definition.spec();
        if !spec.dependencies.is_empty()
            || spec.reboot != r::SoftwareReboot::Report
            || spec.downgrade != r::SoftwareDowngrade::Deny
        {
            return Err(Error::Unsupported);
        }
        let (key, identity, invocation, mechanism) =
            match spec.behavior.as_ref().ok_or(Error::Unsupported)? {
                r::SoftwareBehavior::Msi(native) | r::SoftwareBehavior::Pkg(native) => {
                    if native.scope != r::SoftwareScope::System
                        || native.upgrade != r::SoftwareUpgrade::InPlace
                        || native.install != native.upgrade_invocation
                    {
                        return Err(Error::Unsupported);
                    }
                    let (identity, mechanism) = match (
                        spec.behavior.as_ref().ok_or(Error::Unsupported)?,
                        &native.detect,
                    ) {
                        (
                            r::SoftwareBehavior::Msi(_),
                            r::SoftwareDetection::MsiProduct {
                                product_code,
                                version,
                            },
                        ) => (
                            Identity::Msi {
                                product: Uuid::parse_str(product_code.trim_matches(['{', '}']))
                                    .map_err(|_| Error::Unsupported)?,
                                version: version.clone(),
                            },
                            r::SignatureMechanism::Authenticode,
                        ),
                        (
                            r::SoftwareBehavior::Pkg(_),
                            r::SoftwareDetection::PkgReceipt { receipt, version },
                        ) => (
                            Identity::Pkg {
                                receipt: receipt.clone(),
                                version: version.clone(),
                            },
                            r::SignatureMechanism::AppleDeveloperId,
                        ),
                        _ => return Err(Error::Unsupported),
                    };
                    (&native.installer, identity, &native.install, mechanism)
                }
                r::SoftwareBehavior::Msix(msix) => {
                    let r::MsixContainer::Package { installer } = &msix.container else {
                        return Err(Error::Unsupported);
                    };
                    if msix.allow_unsigned
                        || !msix.dependencies.is_empty()
                        || msix.deployment != r::MsixDeployment::DeviceProvisioning
                        || msix.upgrade != r::SoftwareUpgrade::InPlace
                    {
                        return Err(Error::Unsupported);
                    }
                    (
                        installer,
                        Identity::Msix {
                            family: super::identity::family(
                                &msix.identity.name,
                                &msix.identity.publisher,
                            ),
                            identity: msix.identity.clone(),
                        },
                        &msix.invocation,
                        r::SignatureMechanism::Msix,
                    )
                }
                _ => return Err(Error::Unsupported),
            };
        if invocation.run_as != r::RunAs::System
            || !invocation.environment.is_empty()
            || !invocation.arguments.is_empty()
            || invocation.exit_codes.success != [0].into_iter().collect()
            || !invocation.exit_codes.reboot.is_empty()
        {
            return Err(Error::Unsupported);
        }
        if matches!(identity, Identity::Msi { .. })
            && (invocation.timeout_seconds > 255 * 60 || invocation.timeout_seconds % 60 != 0)
        {
            return Err(Error::Unsupported);
        }
        let signature = spec
            .signatures
            .iter()
            .find(|s| &s.artifact == key && s.mechanism == mechanism && s.evidence.is_some())
            .ok_or(Error::Unsupported)?;
        if let Identity::Msix { identity, .. } = &identity
            && signature.publisher != identity.publisher
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            identity,
            artifact: spec.artifacts.get(key).ok_or(Error::Input)?.clone(),
            origin,
            timeout_seconds: invocation.timeout_seconds,
            minimum_os: match spec.behavior.as_ref().ok_or(Error::Unsupported)? {
                r::SoftwareBehavior::Msix(m) => Some(m.minimum_os),
                _ => None,
            },
        })
    }
    pub fn effect_version(&self) -> String {
        match &self.identity {
            Identity::Msi { version, .. } | Identity::Pkg { version, .. } => version.clone(),
            Identity::Msix { identity, .. } => identity.version.map(|v| v.to_string()).join("."),
        }
    }
    pub fn effect_identity(&self) -> String {
        match &self.identity {
            Identity::Msi { product, .. } => format!("msi:{product}"),
            Identity::Msix { family, .. } => format!("msix:{family}"),
            Identity::Pkg { receipt, .. } => format!("pkg:{receipt}"),
        }
    }
    pub fn task(
        &self,
        operation: Uuid,
        protection: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
    ) -> std::result::Result<crate::deployment::Task, Error> {
        let token = protection
            .mac(
                &serde_json::to_vec(&self.artifact).map_err(|_| Error::Input)?,
                &aad(tenant, "software.download", &operation)?,
            )
            .map_err(|_| Error::Integrity)?
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let url = format!(
            "{}/api/v1/software/installations/{operation}/package?token={token}",
            self.origin.trim_end_matches('/')
        );
        Ok(match &self.identity {
            Identity::Msi { product, version } => crate::deployment::Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::Msi {
                    job: rss_mdm_windows_mdm::software::InstallJob {
                        product: product.to_string(),
                        version: version.clone(),
                        content_urls: vec![url],
                        sha256: self.artifact.sha256,
                        operation: operation.to_string(),
                        scope: rss_mdm_windows_mdm::native::Scope::Device,
                        enforcement: rss_mdm_windows_mdm::software::Enforcement {
                            command_line: "/quiet /norestart".into(),
                            timeout_minutes: u8::try_from(self.timeout_seconds.div_ceil(60))
                                .map_err(|_| Error::Unsupported)?,
                            retry_count: 0,
                            retry_interval_minutes: 5,
                            download_from_aad: false,
                        },
                    },
                },
            },
            Identity::Msix { family, .. } => crate::deployment::Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl {
                    request: rss_mdm_windows_mdm::software::MsixInstall::new(family.clone(), url)
                        .and_then(|v| v.request())
                        .map_err(|_| Error::Input)?,
                },
            },
            Identity::Pkg { receipt, version } => {
                use rss_mdm_apple_mdm::native::{
                    input::{CommandInput, Fields},
                    request::Request,
                };
                let mut body = rss_mdm_apple_mdm::software::installation_manifest(
                    receipt,
                    version,
                    &url,
                    self.artifact.sha256,
                )
                .map_err(|_| Error::Input)?;
                body.remove("RequestType");
                crate::deployment::Task::Macos {
                    request: Request::Command {
                        command: CommandInput {
                            request_type: "InstallEnterpriseApplication".into(),
                            fields: Fields::from_plist(&body).map_err(|_| Error::Input)?,
                        },
                    },
                }
            }
        })
    }
}

fn aad(
    tenant: rss_request_context::TenantId,
    purpose: &str,
    identity: &Uuid,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    rss_mdm_native_protection::canonical::aad(tenant, purpose, identity).map_err(|_| Error::Input)
}

impl Package {
    pub fn observation(&self) -> Option<rss_mdm_windows_mdm::native::Request> {
        use rss_mdm_windows_mdm::native::{Request, Verb};
        let Identity::Msix { family, identity } = &self.identity else {
            return None;
        };
        let architecture = match identity.architecture {
            r::MsixArchitecture::X86_64 => "x64",
            r::MsixArchitecture::Aarch64 => "arm64",
            r::MsixArchitecture::Neutral => "neutral",
        };
        let publisher = family.rsplit_once('_')?.1;
        let version = identity.version.map(|v| v.to_string()).join(".");
        let full = format!(
            "{}_{version}_{architecture}_{}_{publisher}",
            identity.name, identity.resource_id
        );
        let mut operations:Vec<_>=["Status","LastError"].into_iter().map(|property|Request::Node { node:format!("./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppInstallation/*/{property}"),instance:vec![family.clone()],operation:Verb::Get,value:None }).collect();
        for property in ["IsProvisioned", "Version"] {
            operations.push(Request::Node {node:format!("./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/nonStore/*/*/{property}"),instance:vec![family.clone(),full.clone()],operation:Verb::Get,value:None});
        }
        Some(Request::Sequence { operations })
    }
}
