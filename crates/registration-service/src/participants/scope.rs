//! Registration consumes Scope qualifications and current association evidence on the borrowed connection.
use rss_mdm_agent_wire::ObjectRef;
use serde::{Deserialize, Serialize};
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
    pub targets: Vec<crate::device::endpoints::PrimaryRegistration>,
    pub after: Option<rss_mdm_agent_wire::DeviceId>,
    pub has_more: bool,
    pub scanned: u64,
}
/// Existing immutable resolution, including unmatched rows used to explain a draft.
#[derive(Clone, Debug)]
pub struct ScopePreview {
    pub result: Uuid,
    pub devices: Vec<rss_mdm_agent_wire::DeviceId>,
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
    pub target: Option<crate::device::endpoints::PrimaryRegistration>,
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
    pub members: Vec<crate::device::endpoints::PrimaryRegistration>,
}

#[derive(Clone, Debug)]
pub struct ObjectChange {
    pub position: i64,
    pub object: rss_mdm_agent_wire::ObjectRef,
    pub old_devices: Vec<rss_mdm_agent_wire::DeviceId>,
    pub new_devices: Vec<rss_mdm_agent_wire::DeviceId>,
}

use rss_request_context::TenantId;

use sqlx::PgConnection;

pub trait Sources: Send + Sync {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile;
    fn preview_scope_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<rss_mdm_agent_wire::DeviceId>,
    ) -> Pending<'a, ScopePreview>;
    fn assignment_objects_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<rss_mdm_agent_wire::ObjectRef>,
        limit: usize,
    ) -> Pending<'a, Vec<AssignmentObject>>;
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Vec<DeviceObject>>;
    fn evidence_valid_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        channel: Channel,
        device: &'a rss_mdm_agent_wire::DeviceId,
        evidence: &'a [DeviceObject],
    ) -> Pending<'a, bool>;
    fn admission_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, ScopeAdmission>;
    fn query_coordinate_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
    ) -> Pending<'a, String>;
}
