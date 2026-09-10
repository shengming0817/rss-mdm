//! Process diagnostics contain controlled categories, never provider error text or input values.
use crate::Error;
use serde::Serialize;
use std::path::PathBuf;
/// The composition root supplies the monotonic source explicitly.
pub struct Monotonic(pub fn() -> std::time::Instant);
impl rss_observation::Clock for Monotonic {
    fn now(&self) -> std::time::Instant {
        (self.0)()
    }
}
/// Closed categories: no configuration values or provider messages are retained.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    Listen,
    DatabaseRole,
    AccessDatabase,
    DatabaseAddress,
    DatabasePassword,
    DatabaseCa,
    ProductOrigin,
    IdentityOrigin,
    Issuer,
    CookieAuthority,
    Tenant,
    ClientId,
    Bindings,
    FileAccess,
    FileShape,
    FileSize,
    SecretEncoding,
    SecretContents,
    OidcSecret,
    ValidationSecret,
    DistinctSecrets,
    IdentityCa,
    OidcEndpoints,
    OidcAlgorithms,
    IdentityClient,
    Budget,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    RequestDeadline,
    IdentityTransport,
    IdentityValidation,
    IdentityDeadline,
    IdentityProtocol,
    IdentityServer,
    InventoryPool,
    AccessStore,
    AccessAdmission,
    Audit,
    InventoryQuery,
    Observation,
    Clock,
    SessionState,
    Capacity,
    Runtime,
}
#[derive(Clone, Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("{stage}: configuration {issue:?} rejected")]
    Configuration {
        stage: &'static str,
        issue: ConfigIssue,
    },
    #[error("{stage}: {reason:?}")]
    Dependency {
        stage: &'static str,
        reason: Failure,
    },
    #[error("configuration file unavailable or unsafe: {0:?}")]
    ConfigFile(PathBuf),
    #[error("configuration JSON rejected at line {line}, column {column}: {path:?}")]
    ConfigJson {
        path: PathBuf,
        line: usize,
        column: usize,
    },
    #[error("{stage}: {kind}")]
    Stage {
        stage: &'static str,
        kind: &'static str,
    },
    #[error("{stage}: {kind:?}")]
    Io {
        stage: &'static str,
        kind: std::io::ErrorKind,
    },
    #[error(transparent)]
    Migration(#[from] crate::migration::MigrationError),
}
impl ProcessError {
    pub fn at(stage: &'static str, error: Error) -> Self {
        match error {
            Error::Configuration(issue) => Self::Configuration { stage, issue },
            Error::Unavailable(reason) => Self::Dependency { stage, reason },
            _ => Self::Stage {
                stage,
                kind: "operation rejected",
            },
        }
    }
}
