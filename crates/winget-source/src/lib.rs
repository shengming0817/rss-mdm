//! Bounded REST Source 1.0 metadata and complete-version publication; no CLI or installation.
#![deny(missing_docs)]
mod publisher;
mod version;
pub use publisher::{Inspection, Publisher, WriteAccess, WriteResponse};
pub use version::VersionManifest;
mod http;
mod manifest;
pub use http::{Access, Client, Source};
pub use manifest::{Manifest, parse_manifest};
use rss_request_context::TenantId;
use std::fmt;

/// WinGet REST contract negotiated by every request.
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Maximum buffered JSON response or complete-version document size in bytes.
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Credential-free failure classification. A write timeout or transport failure does not prove that no mutation occurred.
pub enum Error {
    /// Input violates the supported identity, URL or configuration contract.
    InvalidInput,
    /// SHA-256 is malformed or differs from the expected digest.
    InvalidDigest,
    /// The source advertises behavior outside the supported contract.
    Unsupported,
    /// The package, source or credential reference does not match.
    IdentityMismatch,
    /// Input and configured source belong to different tenants.
    TenantMismatch,
    /// The requested manifest is absent.
    NotFound,
    /// Multiple installers match one selection identity.
    Ambiguous,
    /// The response cannot be decoded as the supported manifest contract.
    InvalidResponse,
    /// The source returned an unexpected HTTP status at the indicated stage.
    HttpStatus {
        /// Phase that received the response.
        stage: RequestStage,
        /// HTTP response status.
        status: u16,
    },
    /// The total request deadline expired at this stage; writes require reconciliation.
    Timeout(RequestStage),
    /// The configured byte, item or duration budget was exceeded.
    BudgetExceeded,
    /// Transport failed at this stage; writes may already have applied.
    Transport(RequestStage),
    /// The destination violates the reviewed-address policy.
    AddressDenied,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Safe request phase for diagnostics, without credentials or coordinates.
pub enum RequestStage {
    /// Complete-version POST.
    Publish,
    /// Exact-version DELETE.
    Withdraw,
    /// Read-back comparison after a write.
    Reconcile,
    /// Client construction.
    Setup,
    /// Source identity and contract negotiation.
    Information,
    /// Exact installer metadata lookup.
    Manifest,
    /// Bounded installer selection within one package version.
    Query,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "winget source: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Supported installer CPU architecture.
pub enum Architecture {
    /// 64-bit x86 installer.
    X64,
    /// 64-bit ARM installer.
    Arm64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Supported Windows installer technology.
pub enum InstallerType {
    /// Windows Installer package.
    Msi,
    /// Executable installer.
    Exe,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Declared installer scope; unspecified is never promoted to machine scope.
pub enum Scope {
    /// The source did not declare an installation scope. Never treated as machine.
    Unspecified,
    /// Per-user installation.
    User,
    /// Per-machine installation.
    Machine,
}
impl Architecture {
    /// Canonical protocol spelling of this variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }
}
impl InstallerType {
    /// Canonical protocol spelling of this variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Msi => "msi",
            Self::Exe => "exe",
        }
    }
}
impl Scope {
    /// Canonical protocol spelling of this variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::User => "user",
            Self::Machine => "machine",
        }
    }
}
pub(crate) fn identity(s: &str) -> Result<(), Error> {
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || s == "."
        || s == ".."
    {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
pub(crate) fn safe_url(s: &str) -> Result<url::Url, Error> {
    if s.len() > 2048 || s.chars().any(char::is_whitespace) || s.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    let u = url::Url::parse(s).map_err(|_| Error::InvalidInput)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        return Err(Error::InvalidInput);
    }
    Ok(u)
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Bounded installer selection within one package version.
pub struct Query {
    tenant: TenantId,
    source: String,
    package: String,
    version: String,
    architecture: Architecture,
    installer: InstallerType,
    scope: Scope,
    installer_id: Option<String>,
}
impl Query {
    /// Validate tenant/source/package/version and exact installer selection. Package identifiers contain 2–4 dot-separated segments; no I/O is performed.
    pub fn new(
        tenant: TenantId,
        source: &str,
        package: &str,
        version: &str,
        architecture: Architecture,
        installer: InstallerType,
        scope: Scope,
    ) -> Result<Self, Error> {
        for s in [source, package, version] {
            identity(s)?;
        }
        let segments: Vec<_> = package.split('.').collect();
        if !(2..=4).contains(&segments.len())
            || segments.iter().any(|p| p.is_empty() || p.len() > 32)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            tenant,
            source: source.into(),
            package: package.into(),
            version: version.into(),
            architecture,
            installer,
            scope,
            installer_id: None,
        })
    }
    /// Validate and select one exact installer identifier.
    pub fn with_installer_id(mut self, id: &str) -> Result<Self, Error> {
        identity(id)?;
        self.installer_id = Some(id.into());
        Ok(self)
    }
    /// Optional exact installer identity used to disambiguate selection.
    pub fn installer_id(&self) -> Option<&str> {
        self.installer_id.as_deref()
    }
    /// Requested installer architecture.
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }
    /// Requested installer technology.
    pub const fn installer_type(&self) -> InstallerType {
        self.installer
    }
    /// Declared scope, including unspecified.
    pub const fn scope(&self) -> Scope {
        self.scope
    }
    /// Tenant owning this value.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Logical source identifier bound to this tenant.
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Validated package identifier.
    pub fn package(&self) -> &str {
        &self.package
    }
    /// Exact version identifier.
    pub fn version(&self) -> &str {
        &self.version
    }
}
