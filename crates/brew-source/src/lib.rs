#![deny(missing_docs)]
//! Controlled Tap metadata and local Git commits. Never runs Ruby or Homebrew.
//!
//! Render a typed [`Cask`] or [`Formula`] into a [`Document`]. A [`Repository`]
//! binds an authorized tenant/tap to an existing local bare SHA-1 repository.
//! Preparation writes objects; publication separately compares and swaps the main
//! branch. Retain the original operation inputs and [`Prepared`] target to reconcile
//! [`Error::OutcomeUnknown`]. There is no clone, push, artifact download or install.
//! The host owns repository access, authentication and durable operation records.
mod git;
mod template;
pub use git::{CommitId, DocumentPresence, Prepared, PublishResult, Repository, Snapshot};
use rss_request_context::TenantId;
use std::fmt;
pub use template::{Artifact, Bottle, BottleTag, Cask, CaskArtifact, Document, Formula};

/// Maximum rendered document and bounded Git output size in bytes (1 MiB).
pub const MAX_DOCUMENT: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed input and provider failures without raw command arguments or stderr.
/// A failed mutation does not by itself prove that the branch was unchanged.
pub enum Error {
    /// A token, URL, version, count or commit identity violates the supported format.
    InvalidInput,
    /// The repository format or requested template combination is unsupported.
    Unsupported,
    /// An architecture, bottle tag or dependency appears more than once.
    Duplicate,
    /// The document or prepared operation belongs to another tap or repository.
    IdentityMismatch,
    /// An input belongs to a different tenant.
    TenantMismatch,
    /// Artifact SHA-256 or fixed-commit document bytes differ from the expectation.
    DigestMismatch,
    /// A repository path, document tree entry or installation filename is disallowed.
    PathDenied,
    /// The real branch differs from both the original base and prepared target.
    Conflict,
    /// The requested Git object is absent.
    NotFound,
    /// A local filesystem operation or Git output interpretation failed.
    Git,
    /// A Git subprocess could not complete successfully at the given phase.
    GitFailure {
        /// Closed phase label, safe for diagnostics.
        stage: GitStage,
        /// Process exit code when available; absent for spawn/I/O failures or no code.
        exit_code: Option<i32>,
    },
    /// One Git subprocess exceeded its 10-second operation budget.
    GitTimeout(GitStage),
    /// Rendered content or Git output exceeded [`MAX_DOCUMENT`].
    BudgetExceeded,
    /// Branch update failed and read-back could not establish the result.
    /// Retain the same prepared target and original operation inputs; reconcile
    /// branch reachability before deciding whether to retry or report success.
    OutcomeUnknown,
}
/// Safe operation context; never contains argv, paths, URLs or stderr.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitStage {
    /// Repository format, object identity or ancestry inspection.
    Inspect,
    /// Populate a temporary index from a base tree.
    ReadTree,
    /// Write document bytes as an unreachable blob.
    HashObject,
    /// Modify the temporary index.
    UpdateIndex,
    /// Write the prepared tree object.
    WriteTree,
    /// Write the prepared commit object.
    CommitTree,
    /// Read the main branch reference.
    ReadRef,
    /// Compare and swap the main branch reference.
    UpdateRef,
    /// Inspect or read fixed Git tree/blob content.
    ReadObject,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "brew source: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
/// Supported macOS Cask architecture.
pub enum Architecture {
    /// Apple silicon.
    Arm64,
    /// 64-bit Intel.
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
/// Tenant-scoped tap and package identity, without repository authorization.
pub struct PackageKey {
    tenant: TenantId,
    tap: String,
    name: String,
}
impl PackageKey {
    /// Validate a tap of exactly `owner/repository` and one package name.
    /// Each component is 1–128 ASCII bytes, starts with a lowercase letter, and
    /// contains only lowercase letters, digits and single hyphens, with no trailing
    /// hyphen. Invalid input returns [`Error::InvalidInput`]; performs no I/O.
    pub fn new(tenant: TenantId, tap_name: &str, name: &str) -> Result<Self, Error> {
        tap(tap_name)?;
        token(name)?;
        Ok(Self {
            tenant,
            tap: tap_name.into(),
            name: name.into(),
        })
    }
    /// Return the tenant that must match repository and dependency inputs.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Borrow the validated `owner/repository` tap name.
    pub fn tap(&self) -> &str {
        &self.tap
    }
    /// Borrow the validated package token.
    pub fn name(&self) -> &str {
        &self.name
    }
}
