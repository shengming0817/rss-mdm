//! Bounded REST Source 1.0 metadata consumption; no CLI, installation or publishing.
mod http;
mod manifest;
pub use http::{Access, Client, Source};
pub use manifest::{Manifest, parse_manifest};
use rss_request_context::TenantId;
use std::fmt;

pub const CONTRACT_VERSION: &str = "1.0.0";
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInput,
    InvalidDigest,
    Unsupported,
    IdentityMismatch,
    TenantMismatch,
    NotFound,
    Ambiguous,
    InvalidResponse,
    HttpStatus { stage: RequestStage, status: u16 },
    Timeout(RequestStage),
    BudgetExceeded,
    Transport(RequestStage),
    AddressDenied,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestStage {
    Setup,
    Information,
    Manifest,
    Query,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "winget source: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    X64,
    Arm64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerType {
    Msi,
    Exe,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// The source did not declare an installation scope. Never treated as machine.
    Unspecified,
    User,
    Machine,
}
impl Architecture {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }
}
impl InstallerType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Msi => "msi",
            Self::Exe => "exe",
        }
    }
}
impl Scope {
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
    pub fn with_installer_id(mut self, id: &str) -> Result<Self, Error> {
        identity(id)?;
        self.installer_id = Some(id.into());
        Ok(self)
    }
    pub fn installer_id(&self) -> Option<&str> {
        self.installer_id.as_deref()
    }
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }
    pub const fn installer_type(&self) -> InstallerType {
        self.installer
    }
    pub const fn scope(&self) -> Scope {
        self.scope
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn package(&self) -> &str {
        &self.package
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}
