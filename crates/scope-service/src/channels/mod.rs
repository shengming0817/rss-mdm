//! Scope-owned channel qualification and immutable published target facts.
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub use rss_mdm_inventory::Channel;
pub use rss_mdm_inventory_service::objects::{DeviceObject, ObjectRef};

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

/// Scope qualification of an entire endpoint/association for device-owned work.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAssignment {
    pub cursor: String,
    pub object: DeviceObject,
    pub admission: ScopeAdmission,
    pub scope_result: Uuid,
}

mod reader;
pub use reader::{ChannelTargets, query_coordinate_on};
pub mod targets;
