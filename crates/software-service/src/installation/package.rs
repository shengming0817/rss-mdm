//! Frozen Agent installation contracts and checked native package inputs.
use crate::catalog::Error;
use rss_mdm_policy::Platform;
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use rss_mdm_resource as resource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Published package identity binds the reviewed artifact to its native detector.
/// Signing metadata is optional; the native installer owns platform installation decisions.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    WindowsMsi {
        product: Uuid,
        publisher: Option<String>,
    },
    WindowsMsix {
        family: String,
        identity: resource::MsixIdentity,
        minimum_os: [u16; 4],
    },
    Macos {
        receipt: String,
        bundle: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        team: String,
    },
}
impl Identity {
    pub fn platform(&self) -> Platform {
        match self {
            Self::WindowsMsi { .. } | Self::WindowsMsix { .. } => Platform::Windows,
            Self::Macos { .. } => Platform::Macos,
        }
    }
    pub fn validate(&self) -> std::result::Result<(), Error> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        let valid = match self {
            Self::WindowsMsi { product, publisher } => {
                !product.is_nil() && publisher.as_ref().is_none_or(|p| bounded(p))
            }
            Self::WindowsMsix {
                family, identity, ..
            } => bounded(family) && bounded(&identity.name) && bounded(&identity.publisher),
            Self::Macos {
                receipt,
                bundle,
                team,
            } => {
                bounded(receipt)
                    && bounded(bundle)
                    && team.len() <= 256
                    && !team.chars().any(char::is_control)
            }
        };
        if valid { Ok(()) } else { Err(Error::Input) }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub release: rss_mdm_agent_wire::enroll::configuration::Installation,
    pub identity: Identity,
    pub target: SoftwareTarget,
    pub version: String,
    pub artifact: resource::SoftwareArtifact,
    pub source: resource::SoftwareSource,
}
impl Package {
    /// Product admission owns native inputs and the fixed Agent bootstrap arguments.
    pub fn native_task(
        &self,
        operation: Uuid,
        origin: &str,
    ) -> std::result::Result<crate::deployment::model::Task, Error> {
        use crate::deployment::model::Task;
        Ok(match &self.identity {
            Identity::WindowsMsi { .. } => Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::Msi {
                    job: self
                        .windows_job(operation, origin)
                        .map_err(|_| Error::Input)?,
                },
            },
            Identity::WindowsMsix { family, .. } => Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl {
                    request: rss_mdm_windows_mdm::software::MsixInstall::new(
                        family.clone(),
                        self.url(operation, origin),
                    )
                    .and_then(|v| v.request())
                    .map_err(|_| Error::Input)?,
                },
            },
            Identity::Macos { bundle, .. } => {
                use rss_mdm_apple_mdm::native::{
                    input::{CommandInput, Fields},
                    request::Request,
                };
                let mut body = apple_install(
                    bundle,
                    &self.version,
                    &self.url(operation, origin),
                    self.artifact.sha256,
                    operation,
                )
                .map_err(|_| Error::Input)?;
                body.remove("RequestType");
                Task::Macos {
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
    pub fn windows_job(
        &self,
        operation: Uuid,
        origin: &str,
    ) -> std::result::Result<
        rss_mdm_windows_mdm::software::InstallJob,
        rss_mdm_windows_mdm::CodecError,
    > {
        use rss_mdm_windows_mdm::{
            native::Scope,
            software::{Enforcement, InstallJob},
        };
        let Identity::WindowsMsi { product, .. } = &self.identity else {
            return Err(rss_mdm_windows_mdm::CodecError::Unsupported);
        };
        Ok(InstallJob {
            product: product.to_string(),
            version: self.version.clone(),
            content_urls: vec![self.url(operation, origin)],
            sha256: self.artifact.sha256,
            operation: operation.to_string(),
            scope: Scope::Device,
            enforcement: Enforcement {
                command_line: "/quiet /norestart".into(),
                timeout_minutes: 5,
                retry_count: 0,
                retry_interval_minutes: 5,
                download_from_aad: false,
            },
        })
    }
    pub fn url(&self, operation: Uuid, origin: &str) -> String {
        format!(
            "{}/api/v1/agent/enroll/installations/{operation}/package",
            origin.trim_end_matches('/')
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenInstall {
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
    pub packages: BTreeMap<SoftwareTarget, Package>,
    pub actor: rss_mdm_authorization_service::Actor,
}

fn apple_install(
    bundle: &str,
    version: &str,
    url: &str,
    hash: [u8; 32],
    operation: Uuid,
) -> std::result::Result<plist::Dictionary, rss_mdm_apple_mdm::Error> {
    if operation.is_nil() {
        return Err(rss_mdm_apple_mdm::Error::Malformed);
    }
    let mut body = rss_mdm_apple_mdm::software::installation_manifest(bundle, version, url, hash)?;
    body.insert(
        "Configuration".into(),
        rss_mdm_apple_mdm::protocol::dictionary([(
            "RSSInstallationOperation",
            operation.to_string().into(),
        )])
        .into(),
    );
    Ok(body)
}

use rss_mdm_policy::Architecture;
pub fn resource_target(target: SoftwareTarget) -> (resource::Platform, resource::Architecture) {
    let (p, a) = target.parts();
    (
        match p {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        },
        match a {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        },
    )
}

impl Package {
    pub async fn admitted_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> std::result::Result<bool, Error> {
        match crate::agent_packages::admitted_on(c, tenant, &self.release).await {
            Ok(current) => {
                Ok(current.installer_sha256 == self.artifact.sha256
                    && current.version == self.version)
            }
            Err(
                crate::management::Error::Forbidden | crate::management::Error::ResourceMissing,
            ) => Ok(false),
            Err(_) => Err(Error::Dependency),
        }
    }
    pub async fn admitted_snapshot_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> std::result::Result<bool, Error> {
        let packages =
            crate::agent_packages::admitted_many_on(c, tenant, &[self.release.release_id])
                .await
                .map_err(|_| Error::Dependency)?;
        Ok(packages
            .get(&self.release.release_id)
            .is_some_and(|current| {
                current.installer_sha256 == self.artifact.sha256 && current.version == self.version
            }))
    }
    pub fn detection_identity(&self) -> String {
        match &self.identity {
            Identity::WindowsMsi { product, .. } => product.to_string(),
            Identity::WindowsMsix { family, .. } => family.clone(),
            Identity::Macos { bundle, .. } => bundle.clone(),
        }
    }
}
