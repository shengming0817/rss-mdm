#![deny(missing_docs)]
//! Canonical tenant/time types belong to their RSS owners.
//! ```compile_fail
//! use rss_mdm_policy::TenantId;
//! ```
//! ```compile_fail
//! use rss_mdm_policy::Timepoint;
//! ```
//! Policy lifecycle and deterministic intent planning; no storage or dispatch.
//! Callers supply authenticated identities and complete snapshots. Persisting the
//! returned preconditions and intents atomically belongs to the product adapter.
//! Role identities reject same-tenant argument mixups at compile time:
//! ```compile_fail
//! use rss_mdm_policy::{DeviceId, Policy};
//! fn wrong_role(device: DeviceId) { let _ = Policy::draft(device); }
//! ```
//! ```compile_fail
//! use rss_mdm_policy::{Effect, ExecutionRecord, PayloadId, Progress, Version};
//! fn wrong_role(version: Version, payload: PayloadId) {
//!     let _ = ExecutionRecord::new(version, payload, Progress::Planned, Effect::Unverified);
//! }
//! ```
//! Full-target inputs and synchronous full-plan materialization are unavailable.
//! ```compile_fail
//! use rss_mdm_policy::{reconcile, PlanInput, TargetSnapshot};
//! ```
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]
mod fingerprint;
pub use fingerprint::{ExecutionDigest, TargetDigest, stream_plan_id};
mod identity;
mod lifecycle;
pub use identity::{DeviceId, PayloadId, PolicyId, RequestId, TargetSnapshotId};
mod model;
mod plan;
pub use lifecycle::*;
pub use model::*;
pub use plan::*;
