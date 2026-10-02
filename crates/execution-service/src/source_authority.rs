//! Transaction-borrowing source facts supplied by Group/Scope/Policy orchestration.
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, SourceError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ScopeAdmission {
    Eligible { entry: i64 },
    Pending,
    Excluded,
}
#[derive(Clone, Copy, Debug)]
pub struct ScopeSnapshot {
    pub scope: Uuid,
    pub result: Uuid,
    pub definition_revision: i64,
    pub resolution_revision: i64,
}
/// Existing immutable resolution, including unmatched rows used to explain a draft.
#[derive(Clone, Debug)]
pub struct ScopePreview {
    pub result: Uuid,
    pub devices: Vec<String>,
}
#[derive(Clone, Copy, Debug)]
pub enum CandidateKind {
    Configuration,
    AgentInstall,
}
impl CandidateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::AgentInstall => "ensure_agent_installed",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PolicyCandidate {
    pub policy: Uuid,
    pub version: Uuid,
    pub scope: Uuid,
    pub admission: ScopeAdmission,
}
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source missing")]
    Missing,
    #[error("source changed or pending")]
    Conflict,
    #[error("invalid source facts")]
    Invariant,
    #[error("source storage unavailable")]
    Storage(#[from] sqlx::Error),
}
/// Implementations use this connection's snapshot and locks; they never settle a transaction.
pub trait SourceAuthority: Send + Sync {
    fn preview_scope_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        after: Option<&'a str>,
    ) -> Pending<'a, ScopePreview>;
    /// Locks the current resolution until the caller settles; returns its first 65 rows.
    fn assignment_devices_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<String>>;
    fn native_interest_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, bool>;
    fn admission_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission>;
    fn capture_scope_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
    ) -> Pending<'a, ScopeSnapshot>;
    fn candidates_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, Vec<PolicyCandidate>>;
    fn snapshot_devices_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: ScopeSnapshot,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<String>>;
}
