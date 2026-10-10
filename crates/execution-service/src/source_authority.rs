//! Transaction-borrowing source facts supplied by Group/Scope/Policy orchestration.
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub use rss_mdm_inventory::Channel;
pub use rss_mdm_inventory_service::objects::{DeviceObject, ObjectRef};

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, SourceError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ScopeAdmission {
    Eligible { entry: i64 },
    Pending,
    Excluded,
}
pub struct ScopeResult {
    pub run: Uuid,
    pub revision: i64,
}
pub struct RolloutPage {
    pub targets: Vec<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub after: Option<String>,
    pub has_more: bool,
    pub scanned: u64,
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
/// A bounded scan page. Empty items do not mean completion while has_more is true.
pub struct CandidatePage {
    pub items: Vec<PolicyCandidate>,
    pub scanned_after: Uuid,
    pub has_more: bool,
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
    /// Freeze current published root, selected stage and earlier stages, or wait.
    fn rollout_input_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scopes: &'a [Uuid],
    ) -> Pending<'a, Option<Vec<ScopeResult>>>;
    /// One durable statistics page from immutable channel results; no online owner revalidation.
    fn rollout_devices_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        runs: &'a [Uuid],
        after: Option<&'a str>,
    ) -> Pending<'a, RolloutPage>;
    fn preview_scope_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, ScopePreview>;
    /// Locks the current resolution until the caller settles; returns its first 65 rows.
    fn assignment_devices_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<String>>;
    fn assignment_objects_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<AssignmentObject>>;
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, Vec<DeviceObject>>;
    fn evidence_valid_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        channel: Channel,
        device: &'a str,
        evidence: &'a [DeviceObject],
    ) -> Pending<'a, bool>;
    fn policy_readable_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        version: Uuid,
    ) -> Pending<'a, bool>;
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
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission>;
    fn candidates_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, CandidatePage>;
}

/// Derived source-object assignment; unavailable rows do not represent an operation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentObject {
    pub object: ObjectRef,
    pub channel: Channel,
    pub availability: Availability,
    pub reason: Option<String>,
    pub target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub admission: ScopeAdmission,
    pub sources: Vec<DeviceObject>,
    pub scope_result: Uuid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Ready,
    Unavailable,
}

/// Convert the pure authored action channel at the service boundary.
pub fn action_channel(kind: rss_mdm_policy::ActionKind) -> Channel {
    if kind.target_channel() == "mdm" {
        Channel::Mdm
    } else {
        Channel::Agent
    }
}
