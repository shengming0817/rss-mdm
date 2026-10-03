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
    NativeProtection,
    Audit,
    AppleListeners,
    AppleScep,
    AppleProfileSigner,
    AppleApns,
    AppleChallengeWebhook,
    AppleNotifyWebhook,
    Execution,
    Content,
    Flow,
    Publication,
    Listen,
    AccessDatabase,
    RuntimeDatabase,
    DatabaseAddress,
    DatabasePassword,
    DatabaseCa,
    ProductOrigin,
    Instance,
    IdentityDatabase,
    IdentityAuditDatabase,
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
    WindowsPush,
    WindowsPoll,
    EnrollmentCa,
    NativeTls,
    ProtocolKey,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    FlowSource,
    FlowConnection,
    FlowAdmission,
    ContentStorage,
    ContentMetadata,
    ContentInvariant,
    ContentDeadline,
    ContentCleanup,
    CommandStorage,
    CommandInvariant,
    PlanningStorage,
    RequestDeadline,
    IdentityStorage,
    InventoryPool,
    #[serde(rename = "access_store")]
    Database,
    AccessAdmission,
    Audit,
    AuditIntegrity,
    AuditIsolation,
    AuditAdmission,
    AuditContract,
    InventoryQuery,
    ManualQuery,
    CollectionQuery,
    AssetObjectLimit,
    AssetSourceLimit,
    AssetBytesLimit,
    Clock,
    Capacity,
    Runtime,
    Certificate,
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
    #[error("{stage}: {error:?}")]
    Service {
        stage: &'static str,
        error: rss_mdm_flow_service::Error,
    },
    #[error("{stage}: owner={owner} {kind}")]
    Owner {
        stage: &'static str,
        owner: &'static str,
        kind: OwnerDiagnostic,
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
            Error::Flow(error @ rss_mdm_flow_service::Error::Unavailable(_)) => {
                Self::Service { stage, error }
            }
            Error::Execution(e) => Self::Owner {
                stage,
                owner: "execution",
                kind: e.into(),
            },
            Error::Authorization(e) => Self::Owner {
                stage,
                owner: "authorization",
                kind: e.into(),
            },
            Error::Registration(e) => Self::Owner {
                stage,
                owner: "registration",
                kind: e.into(),
            },
            Error::Inventory(e) => Self::Owner {
                stage,
                owner: "inventory",
                kind: e.into(),
            },
            Error::Software(e) => Self::Owner {
                stage,
                owner: "software",
                kind: e.into(),
            },
            Error::Content(e) => Self::Owner {
                stage,
                owner: "content",
                kind: OwnerDiagnostic::Content(e),
            },
            Error::ContentRequest(e) => Self::Owner {
                stage,
                owner: "content",
                kind: e.into(),
            },
            error => Self::Stage {
                stage,
                kind: match error {
                    Error::CommitUnknown
                    | Error::Flow(rss_mdm_flow_service::Error::CommitUnknown) => {
                        "commit_unknown; retry_same_operation"
                    }
                    Error::RollbackFailed
                    | Error::Flow(rss_mdm_flow_service::Error::RollbackFailed) => {
                        "rollback_unconfirmed; retry_same_operation"
                    }
                    Error::Conflict | Error::Flow(rss_mdm_flow_service::Error::Conflict) => {
                        "conflict"
                    }
                    Error::Malformed | Error::Flow(rss_mdm_flow_service::Error::Malformed) => {
                        "malformed_input"
                    }
                    Error::Unauthorized
                    | Error::Flow(rss_mdm_flow_service::Error::Unauthorized) => "unauthorized",
                    Error::Forbidden | Error::Flow(rss_mdm_flow_service::Error::Forbidden) => {
                        "forbidden"
                    }
                    _ => "operation rejected",
                },
            },
        }
    }
}

#[cfg(test)]
#[path = "../tests/diagnostic/unit.rs"]
mod tests;

/// Only closed owner categories; never retains provider errors or request values.
#[derive(Clone, Debug)]
pub enum OwnerDiagnostic {
    Malformed,
    Unauthorized,
    Forbidden,
    Conflict,
    Missing,
    Unsupported,
    Corrupt,
    Storage,
    Configuration,
    Deadline,
    Capacity,
    Runtime,
    Retirement,
    CommitUnknown,
    RollbackFailed,
    Audit(rss_mdm_audit_integration::ErrorClass),
    ExecutionConfiguration(rss_mdm_execution_service::ConfigIssue),
    ExecutionDependency(rss_mdm_execution_service::Failure),
    WindowsDeclaredEnrollmentNotReady,
    Inventory(rss_mdm_inventory_service::Failure),
    Software(rss_mdm_software_service::management::Failure),
    Content(rss_mdm_content_service::Error),
}
impl std::fmt::Display for OwnerDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommitUnknown => f.write_str("commit_unknown; retry_same_operation"),
            Self::RollbackFailed => f.write_str("rollback_unconfirmed; retry_same_operation"),
            _ => write!(f, "{self:?}"),
        }
    }
}
impl From<rss_mdm_execution_service::Error> for OwnerDiagnostic {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        use rss_mdm_execution_service::Error as E;
        match e {
            E::Malformed | E::CertificateRequest => Self::Malformed,
            E::Conflict => Self::Conflict,
            E::WindowsDeclaredEnrollmentNotReady => Self::WindowsDeclaredEnrollmentNotReady,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Unsupported => Self::Unsupported,
            E::NotFound | E::Execution(_) | E::Resource(_) | E::Publication(_) => Self::Missing,
            E::Configuration(c) => Self::ExecutionConfiguration(c),
            E::Unavailable(f) => Self::ExecutionDependency(f),
        }
    }
}
impl From<rss_mdm_authorization_service::Error> for OwnerDiagnostic {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Deadline => Self::Deadline,
            E::Configuration => Self::Configuration,
            E::Corrupt => Self::Corrupt,
            E::Storage => Self::Storage,
            E::Audit(e) => Self::Audit(e.class()),
        }
    }
}
impl From<rss_mdm_registration_service::Error> for OwnerDiagnostic {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Deadline => Self::Deadline,
            E::Configuration => Self::Configuration,
            E::Corrupt => Self::Corrupt,
            E::Storage => Self::Storage,
            E::Audit(e) => Self::Audit(e.class()),
            E::Capacity => Self::Capacity,
            E::Runtime => Self::Runtime,
            E::Retirement => Self::Retirement,
            E::NotFound => Self::Missing,
        }
    }
}
impl From<rss_mdm_inventory_service::Error> for OwnerDiagnostic {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        use rss_mdm_inventory_service::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Group(_) | E::NotFound => Self::Missing,
            E::Unavailable(f) => Self::Inventory(f),
            E::Audit(e) => Self::Audit(e.class()),
        }
    }
}
impl From<rss_mdm_software_service::management::Error> for OwnerDiagnostic {
    fn from(e: rss_mdm_software_service::management::Error) -> Self {
        use rss_mdm_software_service::management::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::Unsupported => Self::Unsupported,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::ResourceMissing | E::Publication(_) => Self::Missing,
            E::Unavailable(f) => Self::Software(f),
            E::Authorization(e) => e.into(),
            E::Audit(e) => Self::Audit(e.class()),
        }
    }
}
impl From<rss_mdm_content_service::service::Error> for OwnerDiagnostic {
    fn from(e: rss_mdm_content_service::service::Error) -> Self {
        use rss_mdm_content_service::service::Error as E;
        match e {
            E::Content(e) => Self::Content(e),
            E::Authorization(e) => e.into(),
            E::Audit(e) => Self::Audit(e.class()),
            E::Malformed => Self::Malformed,
            E::Conflict => Self::Conflict,
            E::Forbidden => Self::Forbidden,
            E::Missing => Self::Missing,
            E::Unsupported => Self::Unsupported,
            E::Clock | E::Import | E::Storage => Self::Storage,
            E::Invariant => Self::Corrupt,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
        }
    }
}
