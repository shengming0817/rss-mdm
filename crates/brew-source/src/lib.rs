//! Controlled Tap metadata and local Git commits. Never runs Ruby or Homebrew.
mod git;
mod template;
pub use git::{CommitId, Prepared, PublishResult, Repository, Snapshot};
use rss_request_context::TenantId;
use std::fmt;
pub use template::{Artifact, Bottle, BottleTag, Cask, CaskArtifact, Document, Formula};

pub const MAX_DOCUMENT: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInput,
    Unsupported,
    Duplicate,
    IdentityMismatch,
    TenantMismatch,
    DigestMismatch,
    PathDenied,
    Conflict,
    NotFound,
    Git,
    Timeout,
    BudgetExceeded,
    OutcomeUnknown,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "brew source: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Architecture {
    Arm64,
    Intel,
}
pub(crate) fn token(s: &str) -> Result<(), Error> {
    if s.is_empty()
        || s.len() > 128
        || !s.as_bytes()[0].is_ascii_lowercase()
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || s.ends_with('-')
        || s.contains("--")
    {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
pub(crate) fn tap(s: &str) -> Result<(), Error> {
    let parts: Vec<_> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidInput);
    }
    for p in parts {
        token(p)?;
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageKey {
    tenant: TenantId,
    tap: String,
    name: String,
}
impl PackageKey {
    pub fn new(tenant: TenantId, tap_name: &str, name: &str) -> Result<Self, Error> {
        tap(tap_name)?;
        token(name)?;
        Ok(Self {
            tenant,
            tap: tap_name.into(),
            name: name.into(),
        })
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn tap(&self) -> &str {
        &self.tap
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}
/// References only; not resolved or written into Tap content.
#[derive(Clone)]
pub struct AccessBinding {
    tenant: TenantId,
    tap: String,
    git_credential: String,
    artifact_credential: String,
}
impl AccessBinding {
    pub fn new(
        tenant: TenantId,
        tap_name: &str,
        git_credential: &str,
        artifact_credential: &str,
    ) -> Result<Self, Error> {
        tap(tap_name)?;
        token(git_credential)?;
        token(artifact_credential)?;
        Ok(Self {
            tenant,
            tap: tap_name.into(),
            git_credential: git_credential.into(),
            artifact_credential: artifact_credential.into(),
        })
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn tap(&self) -> &str {
        &self.tap
    }
    pub fn git_credential(&self) -> &str {
        &self.git_credential
    }
    pub fn artifact_credential(&self) -> &str {
        &self.artifact_credential
    }
}
impl fmt::Debug for AccessBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessBinding([redacted])")
    }
}
