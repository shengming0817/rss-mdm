//! Authorized product runtime projection; App supplies the actual component owners.
//! ref: axum axum/src/middleware/from_fn.rs@axum-v0.8.9 (request extensions).
use crate::{Error, authorization::context::RequestAuth};
use axum::{Extension, Json, Router, extract::State, routing::get};
use futures::future::BoxFuture;
use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use serde::Serialize;
use std::{sync::Arc, time::Instant};

/// One absolute host deadline, frozen before loading authorization.
#[derive(Clone, Copy)]
pub struct RequestDeadline(pub Instant);
/// The host must recheck its exact tenant/instance binding before observing components.
pub trait Source: Send + Sync {
    fn snapshot<'a>(
        &'a self,
        tenant: TenantId,
        instance: &'a str,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Snapshot, Error>>;
}
#[derive(Serialize)]
pub struct Snapshot {
    pub alive: bool,
    pub ready: bool,
    pub components: Vec<Component>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub name: ComponentName,
    pub readiness: Readiness,
    /// Current diagnostic observation, independent of the public readiness predicate.
    pub health: Health,
    pub reasons: Vec<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<Task>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub queues: Vec<Queue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run: Option<LastRun>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<Dispatch>,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentName {
    Inventory,
    IdentityAudit,
    Apple,
    Automation,
    ExecutionRecovery,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Ready,
    NotReady,
    NotApplicable,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Degraded,
    Unknown,
    NotApplicable,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Task {
    Unknown,
    Pending,
    Running,
    Cancelled,
    Completed,
    Failed,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Initializing,
    Stopping,
    WorkerNotRunning,
    DeliveryRetrying,
    DependencyUnavailable,
    Deadline,
    SettlementUnknown,
    AutomationSuspended,
    PushUnavailable,
    CertificateExpired,
    ClockUnavailable,
    Unobserved,
    ProjectionFailed,
    OwnershipLost,
    WorkRejected,
}
#[derive(Serialize)]
pub struct Dependency {
    pub name: DependencyName,
    pub state: DependencyState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyName {
    InventoryDelivery,
    ObservationJournal,
    FlowStorage,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyState {
    Available,
    Unavailable,
}
#[derive(Serialize)]
pub struct Queue {
    pub name: QueueName,
    /// None means the query did not succeed; it is never a zero backlog assertion.
    pub count: Option<u64>,
    pub truncated: Option<bool>,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueName {
    DeliveryPending,
    Pending,
    Running,
    Completed,
    Failed,
    Superseded,
    AssetChangesPending,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub state: ProgressState,
    pub confirmed_position: Option<u64>,
    pub source_head: Option<u64>,
    /// This is a coordinate comparison, not an event count or an atomic snapshot.
    pub lagging: Option<bool>,
    pub invocation_age_ms: Option<u64>,
    pub completed_pass_age_ms: Option<u64>,
    pub source_observation_age_ms: Option<u64>,
    pub applied: Option<u64>,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressState {
    Unobserved,
    Pending,
    Running,
    CaughtUp,
    Limited,
    Failed,
    Unavailable,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRun {
    pub successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    pub observed_at: Option<i64>,
}

pub fn routes() -> Router<Arc<dyn Source>> {
    Router::new().route("/runtime/diagnostics", get(read))
}
async fn read(
    State(source): State<Arc<dyn Source>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(deadline): Extension<RequestDeadline>,
) -> Result<Json<Snapshot>, Error> {
    audit.set_action("runtime_diagnostics_read");
    audit.target("runtime");
    auth.proof
        .manage(rss_mdm_authorization_service::Permission::RuntimeDiagnosticsRead)?;
    let tenant = TenantId::parse(auth.proof.tenant_id())
        .map_err(|_| Error(rss_mdm_flow_service::Error::Unauthorized))?;
    source
        .snapshot(tenant, auth.proof.instance_id(), deadline.0)
        .await
        .map(Json)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dispatch {
    pub consumed: u64,
    pub watermark: u64,
}
