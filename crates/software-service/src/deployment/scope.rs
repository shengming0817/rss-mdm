//! Software consumes Scope qualifications and current association evidence on the borrowed connection.
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub use rss_mdm_inventory::Channel;

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, SourceError>> + Send + 'a>>;

#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
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
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source capability is not configured for this product")]
    Unsupported,
    #[error("source read budget exceeded")]
    Capacity,
    #[error("source missing")]
    Missing,
    #[error("source changed or pending")]
    Conflict,
    #[error("invalid source facts")]
    Invariant,
    #[error("source storage unavailable")]
    Storage(#[from] sqlx::Error),
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
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Ready,
    Unavailable,
}

#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceObject {
    pub object: ObjectRef,
    pub association_version: Option<i64>,
    pub verified: bool,
    pub members: Vec<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
}

#[derive(
    schemars::JsonSchema, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObjectRef {
    /// One original endpoint.
    Endpoint(String),
    /// One product association whose members must be resolved by its owner.
    Association(Uuid),
}

#[derive(Clone, Debug)]
pub struct ObjectChange {
    pub position: i64,
    pub object: String,
    pub old_devices: Vec<String>,
    pub new_devices: Vec<String>,
}

use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
impl ObjectRef {
    pub fn key(&self) -> String {
        match self {
            Self::Endpoint(id) => format!("endpoint:{id}"),
            Self::Association(id) => format!("association:{id}"),
        }
    }
}

pub trait Sources: Send + Sync {
    fn rollout_input_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scopes: &'a [Uuid],
        channel: Channel,
    ) -> Pending<'a, Option<Vec<ScopeResult>>>;
    fn rollout_devices_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        runs: &'a [Uuid],
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, RolloutPage>;
    fn preview_scope_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, ScopePreview>;
    fn assignment_objects_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
        limit: usize,
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
    fn admission_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission>;
    fn query_coordinate_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
    ) -> Pending<'a, String>;
    fn channel_state_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission>;
    fn effect_devices<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, Vec<String>>;
    fn change_head<'a>(&'a self, c: &'a mut PgConnection, tenant: TenantId) -> Pending<'a, i64>;
    fn changes<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        after: i64,
        through: i64,
        limit: usize,
    ) -> Pending<'a, Vec<ObjectChange>>;
}
