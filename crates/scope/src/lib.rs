#![deny(missing_docs)]
//! Canonical tenant/time types belong to their RSS owners.
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
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]

mod identity;
pub use identity::{DeviceId, GroupId};
mod model;
pub use model::*;
mod device;
pub use device::{DeviceInput, Membership, SourceMembership, resolve_device};
use std::collections::{BTreeMap, BTreeSet};

mod definition;
pub use definition::{Reference, ScopeDefinition};
