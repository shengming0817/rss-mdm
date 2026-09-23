#![deny(missing_docs)]
//! Canonical tenant/time types belong to their RSS owners.
//! ```compile_fail
//! use rss_mdm_scope::TenantId;
//! ```
//! ```compile_fail
//! use rss_mdm_scope::Timepoint;
//! ```
//! Deterministic per-device scope algebra over immutable source membership.
//! Storage, source authorization and group expansion belong to the caller.
//! Group references cannot become device members through an accidental argument swap:
//! ```compile_fail
//! use rss_mdm_scope::{GroupId, DeviceInput};
//! fn wrong_role(group: GroupId, input: &mut DeviceInput) { input.device = group; }
//! ```
//! ```compile_fail
//! use rss_mdm_scope::{GroupId, SourceId};
//! fn wrong_role(group: GroupId) { let _ = SourceId::Direct(group); }
//! ```
//! Full-collection entry points are deliberately unavailable.
//! ```compile_fail
//! use rss_mdm_scope::{resolve, ScopeInput};
//! ```
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]

mod identity;
pub use identity::{DeviceId, GroupId};
mod model;
pub use model::*;
mod device;
pub use device::{DeviceInput, Membership, SourceMembership, resolve_device};
use std::collections::{BTreeMap, BTreeSet};
