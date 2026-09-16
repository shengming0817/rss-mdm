//! Controlled backend use cases. Management HTTP identity/authorization belongs to N12.
mod artifact;
mod config;
mod driver;
mod service;
mod spec;
mod storage;
pub use artifact::{ArtifactOrigin, ArtifactReader};
pub use config::{BrewConfig, RingSources, ServiceActors, SourceConfig, WingetConfig};
pub use driver::Withdrawal;
use rss_transactional_messaging_postgres::PgError;
pub use service::{CandidateInput, PublicationService, ServiceRequest};
pub use spec::{
    BottleInput, BrewArtifact, BrewDependency, BrewPayload, BrewRecipe, CaskInstall,
    PublicArtifact, Submission, winget_variant,
};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Sanitized lower-level failure with its owning operation stage.
    #[error("{stage}: {category}: {source}")]
    Diagnostic {
        stage: &'static str,
        category: Box<Error>,
        #[source]
        source: SafeCause,
    },
    #[error("invalid publication input")]
    Input,
    #[error("service identity or source binding rejected")]
    Identity,
    #[error("resource or complete version content mismatch")]
    Content,
    #[error("publication state or revision conflict")]
    Conflict,
    #[error("unresolved source mutation blocks this operation")]
    Blocked,
    #[error("public artifact address not allowed")]
    ArtifactAddress,
    #[error("public artifact budget exceeded")]
    ArtifactBudget,
    #[error("public artifact length or digest mismatch")]
    ArtifactDigest,
    #[error("public artifact transport failed")]
    ArtifactTransport,
    #[error("public artifact deadline exceeded")]
    ArtifactTimeout,
    #[error("software source operation failed or uncertain")]
    Source,
    #[error("transaction not started: {0}")]
    NotStarted(PgError),
    #[error("transaction rolled back: {0}")]
    RolledBack(PgError),
    #[error("rollback unconfirmed: {0}")]
    RollbackFailed(PgError),
    #[error("commit unconfirmed; reconcile original identity: {0}")]
    CommitUnknown(PgError),
    #[error("transaction fenced: {0}")]
    Fenced(PgError),
    #[error("resource persistence: {0}")]
    Resource(#[from] rss_mdm_resource_postgres::Error),
    #[error("release persistence: {0}")]
    Release(#[from] rss_mdm_software_release_postgres::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
type InTransaction<T> = std::result::Result<Result<T>, PgError>;
fn settle<T>(
    a: rss_transactional_messaging::transaction::LocalTxAttempt<Result<T>, PgError>,
) -> Result<T> {
    a.fold(
        |v| v,
        |e| Err(Error::NotStarted(e)),
        |e| Err(Error::RolledBack(e)),
        |e| Err(Error::RollbackFailed(e)),
        |e| Err(Error::CommitUnknown(e)),
        |e| Err(Error::Fenced(e)),
    )
}
macro_rules! input {
    ($v:expr) => {
        match $v {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        }
    };
}
use input;
pub const MIGRATION_SQL: &str = include_str!("../../migrations/0006_software_publication.sql");
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
struct PublicationClock;
impl rss_request_context::Clock for PublicationClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "product composition chooses the monotonic deadline clock"
    )]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
fn budget(
    cutoff: rss_request_context::Deadline,
) -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_cutoff(cutoff, &PublicationClock)
}

/// Credential-free cause projection. Raw messages and source values are never retained.
#[derive(Debug, thiserror::Error)]
#[error("{kind}: {reason}")]
pub struct SafeCause {
    kind: &'static str,
    reason: String,
}
impl SafeCause {
    fn of<E: 'static>(error: E) -> Self {
        let value = &error as &dyn std::any::Any;
        let reason = if let Some(e) = value.downcast_ref::<serde_json::Error>() {
            format!("{:?} at {}:{}", e.classify(), e.line(), e.column())
        } else if let Some(e) = value.downcast_ref::<reqwest::Error>() {
            if e.is_timeout() {
                "timeout".into()
            } else if e.is_connect() {
                "connect".into()
            } else if e.is_body() {
                "body".into()
            } else {
                "transport".into()
            }
        } else if let Some(e) = value.downcast_ref::<std::io::Error>() {
            format!("{:?}", e.kind())
        } else if let Some(e) = value.downcast_ref::<rss_mdm_winget_source::Error>() {
            format!("{e:?}")
        } else if let Some(e) = value.downcast_ref::<rss_mdm_brew_source::Error>() {
            format!("{e:?}")
        } else if let Some(e) = value.downcast_ref::<rss_mdm_software_release::Error>() {
            format!("{e:?}")
        } else if let Some(e) = value.downcast_ref::<rss_mdm_resource::Error>() {
            format!("{e:?}")
        } else if let Some(e) = value.downcast_ref::<rss_mdm_resource_postgres::Rejection>() {
            format!("{e:?}")
        } else if let Some(e) = value.downcast_ref::<rss_mdm_software_release_postgres::Rejection>()
        {
            format!("{e:?}")
        } else {
            "rejected".into()
        };
        Self {
            kind: std::any::type_name::<E>(),
            reason,
        }
    }
}
impl Error {
    fn context<E: 'static>(self, stage: &'static str, source: E) -> Self {
        Self::Diagnostic {
            stage,
            category: Box::new(self),
            source: SafeCause::of(source),
        }
    }
}
#[cfg(test)]
mod diagnostics_tests {
    use super::*;
    #[test]
    fn source_kind_and_stage_survive_without_secret() {
        let error = serde_json::from_str::<u64>("\"credential-secret\"").unwrap_err();
        let error = Error::Content.context("complete-version-decode", error);
        let rendered = format!("{error:?} {error}");
        assert!(rendered.contains("complete-version-decode"));
        assert!(rendered.contains("Data"));
        assert!(!rendered.contains("credential-secret"));
        assert!(std::error::Error::source(&error).is_some());
    }
}
