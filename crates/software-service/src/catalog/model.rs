use super::{Error, Result};
use rss_mdm_resource::{SoftwareSource, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
/// Current source protocol, without invalid kind/location combinations or credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceProtocol {
    /// Private enterprise authoring.
    Private,
    /// Existing exact REST source, distinct from our hosted output.
    WingetRest {
        location: String,
        identifier: String,
    },
    /// Official community YAML at one complete commit.
    WingetCommunity { repository: String, commit: String },
    /// Controlled Cask/Formula source at one complete commit.
    BrewTap {
        repository: String,
        tap: String,
        commit: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDefinition {
    pub id: String,
    pub revision: String,
    pub protocol: SourceProtocol,
}
fn source_url(value: &str) -> Result<()> {
    let u = url::Url::parse(value).map_err(|_| Error::Input)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || value.len() > 2048
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn source_commit(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(Error::Input);
    }
    Ok(())
}
impl SourceDefinition {
    pub fn snapshot(&self) -> Result<SoftwareSource> {
        rss_mdm_resource::Id::new(&self.id).map_err(|_| Error::Input)?;
        rss_mdm_resource::Id::new(&self.revision).map_err(|_| Error::Input)?;
        match &self.protocol {
            SourceProtocol::Private => {}
            SourceProtocol::WingetRest {
                location,
                identifier,
            } => {
                source_url(location)?;
                rss_mdm_resource::Id::new(identifier).map_err(|_| Error::Input)?;
            }
            SourceProtocol::WingetCommunity { repository, commit } => {
                source_url(repository)?;
                source_commit(commit)?;
            }
            SourceProtocol::BrewTap {
                repository,
                tap,
                commit,
            } => {
                source_url(repository)?;
                source_commit(commit)?;
                if tap.len() > 255
                    || tap.split('/').count() != 2
                    || tap
                        .split('/')
                        .any(|s| s.is_empty() || s == "." || s == ".." || s.starts_with('-'))
                    || !tap
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
                {
                    return Err(Error::Input);
                }
            }
        }
        Ok(SoftwareSource {
            id: self.id.clone(),
            revision: self.revision.clone(),
            sha256: Sha256::digest(serde_json::to_vec(self).map_err(|_| Error::Input)?).into(),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SourceChange {
    Register { definition: SourceDefinition },
    Approve { evidence: Vec<String> },
    Withdraw { evidence: Vec<String> },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum VersionChange {
    Approve { evidence: Vec<String> },
    Withdraw { evidence: Vec<String> },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation<T> {
    pub operation_id: uuid::Uuid,
    pub expected_revision: u64,
    pub input: T,
}
/// Held until the admission transaction completes. The host must pin every verified artifact.
pub trait VerifiedContent: Send + Sync {
    fn resource_digest(&self) -> [u8; 32];
}
/// Product content owner validates availability, bytes and Bundle layout outside a transaction.
pub type ContentFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Box<dyn VerifiedContent>>> + Send + 'a>,
>;
pub trait ContentPort: Send + Sync {
    fn verify<'a>(&'a self, version: &'a Version) -> ContentFuture<'a>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionState {
    Registered,
    Approved,
    Withdrawn,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Admission {
    pub revision: u64,
    pub state: AdmissionState,
    pub operation: uuid::Uuid,
    pub actor: String,
    pub evidence: Vec<String>,
    pub at: i64,
    pub digest: [u8; 32],
}
/// A current approved variant, retaining its complete Resource-owned definition.
pub struct FrozenSoftware {
    pub(super) source: SourceDefinition,
    pub(super) version: Version,
    pub(super) variant: rss_mdm_resource::Id,
    pub(super) platform: rss_mdm_resource::Platform,
    pub(super) architecture: rss_mdm_resource::Architecture,
    pub(super) admission: Admission,
}
impl FrozenSoftware {
    pub fn source(&self) -> &SourceDefinition {
        &self.source
    }
    pub fn version(&self) -> &Version {
        &self.version
    }
    pub fn variant(&self) -> &rss_mdm_resource::Id {
        &self.variant
    }
    pub fn platform(&self) -> rss_mdm_resource::Platform {
        self.platform
    }
    pub fn architecture(&self) -> rss_mdm_resource::Architecture {
        self.architecture
    }
    pub fn admission(&self) -> &Admission {
        &self.admission
    }
}
pub(super) fn evidence(values: &[String]) -> Result<()> {
    if values.is_empty()
        || values.len() > 32
        || values
            .iter()
            .any(|v| v.is_empty() || v.len() > 1024 || v.chars().any(char::is_control))
    {
        Err(Error::Input)
    } else {
        Ok(())
    }
}
