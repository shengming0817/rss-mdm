//! Process diagnostics contain controlled categories, never provider error text or input values.
use crate::Error;
use serde::Serialize;
use std::path::PathBuf;
/// Install once in the composition root before starting runtime threads.
/// ref: Rust std::panic::set_hook: hooks run before catch_unwind can discard payloads.
pub fn install_diagnostics() -> Result<(), ProcessError> {
    std::panic::set_hook(Box::new(|_| {
        use std::io::Write;
        let _ = writeln!(std::io::stderr().lock(), "{{\"event\":\"mdm_panic\"}}");
    }));
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    // RSS emits closed lifecycle categories. Do not enable provider/HTTP payload logs,
    // environment overrides, or inherited span fields in this product sink.
    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::filter_fn(|meta| {
            meta.is_event() && meta.target() == "rss_axum::server"
        }))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .without_time()
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(std::io::stderr),
        )
        .try_init()
        .map_err(|_| ProcessError::Stage {
            stage: "startup.diagnostics",
            kind: "subscriber installation failed",
        })
}
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
    Commands,
    Management,
    Listen,
    DatabaseRole,
    AccessDatabase,
    RuntimeDatabase,
    DatabaseAddress,
    DatabasePassword,
    DatabaseCa,
    ProductOrigin,
    Instance,
    IdentityDatabase,
    IdentityConfiguration,
    Issuer,
    Tenant,
    FileAccess,
    FileShape,
    FileSize,
    SecretEncoding,
    SecretContents,
    Budget,
    WindowsListeners,
    EnrollmentCa,
    WindowsTls,
    ProtocolKey,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    CommandStorage,
    ManagementAdmission,
    ManagementConnection,
    ManagementSource,
    ManagementStorage,
    RequestDeadline,
    IdentityStorage,
    IdentityValidation,
    IdentityDeadline,
    IdentityProtocol,
    InventoryPool,
    AccessStore,
    AccessAdmission,
    Audit,
    InventoryQuery,
    InventoryRuntime,
    Observation,
    Clock,
    Capacity,
    Runtime,
    Certificate,
    Protocol,
}
#[derive(Clone, Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("lifecycle task={task} reason={reason:?} cleanup_failed={cleanup_failed}")]
    CriticalTask {
        task: String,
        reason: rss_runtime::TaskExit,
        cleanup_failed: bool,
    },
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
            error => Self::Stage {
                stage,
                kind: match error {
                    Error::CommitUnknown => "commit_unknown; retry_same_operation",
                    Error::Conflict => "conflict",
                    Error::Malformed => "malformed_input",
                    Error::Unauthorized => "unauthorized",
                    Error::Forbidden => "forbidden",
                    _ => "operation rejected",
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_unknown_commit_preserves_safe_recovery_class() {
        assert!(
            ProcessError::at("authorization.initialize", Error::CommitUnknown)
                .to_string()
                .contains("retry_same_operation")
        );
        assert_eq!(
            ProcessError::at("authorization.initialize", Error::Conflict).to_string(),
            "authorization.initialize: conflict"
        );
        assert_eq!(
            ProcessError::at("authorization.initialize", Error::Malformed).to_string(),
            "authorization.initialize: malformed_input"
        );
    }
}
