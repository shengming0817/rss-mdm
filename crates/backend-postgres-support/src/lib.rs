#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
mod diagnostic;
mod storage;
pub use diagnostic::*;
pub use storage::*;

/// Closed product namespaces; never populated from configuration or requests.
#[derive(Clone, Copy, Debug)]
pub enum BackendKind {
    /// Policy aggregates, targets and execution facts.
    Policy,
    /// Immutable resource definitions.
    Resource,
    /// Software release candidates and attempts.
    SoftwareRelease,
}
impl BackendKind {
    fn schema(self) -> &'static str {
        match self {
            Self::Policy => "mdm_policy",
            Self::Resource => "mdm_resource",
            Self::SoftwareRelease => "mdm_software_release",
        }
    }
    fn domain(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Resource => "resource",
            Self::SoftwareRelease => "software-release",
        }
    }
}
/// Static product storage policy. Fields describe existing schema, not migrations.
#[derive(Clone, Copy)]
pub struct Admission {
    /// Exact sorted table set, excluding indexes.
    pub tables: &'static [&'static str],
    /// Exact allowed UPDATE columns as table.column values.
    pub update_columns: &'static [&'static str],
    /// Adapter-owned catalog JSON of the existing migration.
    pub catalog: &'static str,
}
/// Borrowed-transaction execution for one product backend.
#[derive(Clone, Copy)]
pub struct BackendStorage {
    kind: BackendKind,
}
impl BackendStorage {
    /// Bind one of the three existing MDM namespaces.
    pub const fn new(kind: BackendKind) -> Self {
        Self { kind }
    }
}
