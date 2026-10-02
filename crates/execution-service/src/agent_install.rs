//! Frozen Agent installation contracts and checked native package inputs.
use crate::Error;
use rss_mdm_authorization_service::UserGrant;
#[cfg(test)]
use rss_mdm_policy::Architecture;
use rss_mdm_policy::{Platform, ResourceBinding};
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use rss_mdm_resource as resource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Deployment pins bind the reviewed product artifact to its claimed signing identity.
/// Production package signature/notarization verification belongs to package publication/T3.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Windows {
        product: Uuid,
        publisher: String,
    },
    Macos {
        receipt: String,
        bundle: String,
        team: String,
    },
}
impl Identity {
    pub fn platform(&self) -> Platform {
        match self {
            Self::Windows { .. } => Platform::Windows,
            Self::Macos { .. } => Platform::Macos,
        }
    }
    pub fn validate(&self) -> std::result::Result<(), Error> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        let valid = match self {
            Self::Windows { product, publisher } => !product.is_nil() && bounded(publisher),
            Self::Macos {
                receipt,
                bundle,
                team,
            } => {
                bounded(receipt)
                    && bounded(bundle)
                    && team.len() == 10
                    && team
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            }
        };
        if valid { Ok(()) } else { Err(Error::Malformed) }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub identity: Identity,
    pub package: String,
    pub version: String,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub content_origin: String,
    pub packages: BTreeMap<SoftwareTarget, Pin>,
}
impl Config {
    pub fn validate(&self) -> std::result::Result<(), Error> {
        if self.packages.is_empty() {
            return if self.content_origin.is_empty() {
                Ok(())
            } else {
                Err(Error::Malformed)
            };
        }
        let origin = url::Url::parse(&self.content_origin).map_err(|_| Error::Malformed)?;
        if self.content_origin.len() > 2048
            || self.content_origin.chars().any(char::is_control)
            || origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(Error::Malformed);
        }
        for (target, pin) in &self.packages {
            pin.identity.validate()?;
            if target.parts().0 != pin.identity.platform()
                || pin.package.is_empty()
                || pin.version.is_empty()
                || pin.sha256 == [0; 32]
            {
                return Err(Error::Malformed);
            }
        }
        // Collection must have one stable product identity for each platform across architectures.
        for platform in [Platform::Windows, Platform::Macos] {
            let mut identities = self
                .packages
                .iter()
                .filter(|(t, _)| t.parts().0 == platform)
                .map(|(_, p)| &p.identity);
            if let Some(first) = identities.next()
                && identities.any(|i| i != first)
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    pub fn identity(&self, platform: Platform) -> Option<&Identity> {
        self.packages
            .iter()
            .find(|(target, _)| target.parts().0 == platform)
            .map(|(_, p)| &p.identity)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub identity: Identity,
    pub target: SoftwareTarget,
    pub version: String,
    pub artifact: resource::SoftwareArtifact,
    pub source: resource::SoftwareSource,
    pub content_origin: String,
}
impl Package {
    /// Product admission owns native inputs and the fixed Agent bootstrap arguments.
    pub fn native_task(&self, operation: Uuid) -> std::result::Result<crate::Task, Error> {
        use crate::Task;
        Ok(match &self.identity {
            Identity::Windows { .. } => Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::Msi {
                    job: self.windows_job(operation).map_err(|_| Error::Malformed)?,
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
                    &self.url(operation),
                    self.artifact.sha256,
                    operation,
                )
                .map_err(|_| Error::Malformed)?;
                body.remove("RequestType");
                Task::Macos {
                    request: Request::Command {
                        command: CommandInput {
                            request_type: "InstallEnterpriseApplication".into(),
                            fields: Fields::from_plist(&body).map_err(|_| Error::Malformed)?,
                        },
                    },
                }
            }
        })
    }
    pub fn windows_job(
        &self,
        operation: Uuid,
    ) -> std::result::Result<
        rss_mdm_windows_mdm::software::InstallJob,
        rss_mdm_windows_mdm::CodecError,
    > {
        use rss_mdm_windows_mdm::{
            native::Scope,
            software::{Enforcement, InstallJob},
        };
        let Identity::Windows { product, .. } = &self.identity else {
            return Err(rss_mdm_windows_mdm::CodecError::Unsupported);
        };
        Ok(InstallJob {
            product: product.to_string(),
            version: self.version.clone(),
            content_urls: vec![self.url(operation)],
            sha256: self.artifact.sha256,
            operation: operation.to_string(),
            scope: Scope::Device,
            enforcement: Enforcement {
                command_line: format!("/quiet /norestart RSS_INSTALLATION_OPERATION={operation}"),
                timeout_minutes: 5,
                retry_count: 0,
                retry_interval_minutes: 5,
                download_from_aad: false,
            },
        })
    }
    pub fn url(&self, operation: Uuid) -> String {
        format!(
            "{}/api/agent/v5/installations/{operation}/package",
            self.content_origin.trim_end_matches('/')
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenInstall {
    pub resource: ResourceBinding,
    pub resource_digest: [u8; 32],
    pub admission_operation: Uuid,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
    pub packages: BTreeMap<SoftwareTarget, Package>,
    pub deploy: UserGrant,
    pub enrollment: UserGrant,
}
#[cfg(test)]
#[path = "../tests/agent_install_unit.rs"]
mod tests;

fn apple_install(
    bundle: &str,
    version: &str,
    url: &str,
    hash: [u8; 32],
    operation: Uuid,
) -> std::result::Result<plist::Dictionary, rss_mdm_apple_mdm::Error> {
    use plist::Value;
    use rss_mdm_apple_mdm::{Error, protocol::dictionary};
    let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
    let location = url::Url::parse(url).map_err(|_| Error::Malformed)?;
    if !bounded(bundle)
        || !bounded(version)
        || hash == [0; 32]
        || operation.is_nil()
        || url.len() > 2048
        || location.scheme() != "https"
        || location.host_str().is_none()
        || !location.username().is_empty()
        || location.password().is_some()
        || location.fragment().is_some()
    {
        return Err(Error::Malformed);
    }
    let hash = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let asset = dictionary([
        ("kind", "software-package".into()),
        ("url", url.into()),
        ("sha256", hash.into()),
    ]);
    let metadata = dictionary([
        ("bundle-identifier", bundle.into()),
        ("bundle-version", version.into()),
        ("kind", "software".into()),
        ("title", "RSS Agent".into()),
    ]);
    let item = dictionary([
        ("assets", Value::Array(vec![asset.into()])),
        ("metadata", metadata.into()),
    ]);
    Ok(dictionary([
        ("RequestType", "InstallEnterpriseApplication".into()),
        (
            "Manifest",
            dictionary([("items", Value::Array(vec![item.into()]))]).into(),
        ),
        (
            "Configuration",
            dictionary([("RSSInstallationOperation", operation.to_string().into())]).into(),
        ),
    ]))
}
