//! Group metadata and immutable paged membership owned by this adapter.
//! The host supplies frozen facts and protects every write with RSS claims.
//! Complete builds are published by pointer; original request identities recover
//! unknown commits. The adapter never owns leases, retries or device execution.
#![deny(missing_docs)]
#![warn(clippy::cognitive_complexity)]

mod admission;
mod codec;
mod decisions;
mod event;
mod generations;
mod presentation;
pub use decisions::{
    DecisionOrigin, DecisionRecord, DecisionValue, FieldEvidence, PredicateDecision,
};
mod model;
pub use generations::{BuildRequest, DifferenceStep, MemberBuild, MemberPatch};
pub mod directory;
mod storage;
mod store;
pub use event::{EVENT_SCHEMA, GroupChangeKind, GroupChanged};
pub use model::*;
/// The same core types used in this adapter's signatures, available to one-package consumers.
pub use rss_mdm_group as core;
pub use store::GroupStore;
/// One-time owner migration; not executable by the runtime role. No legacy upgrade path.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");
#[cfg(test)]
mod codec_tests;

/// Public Outbox function permissions, installed after the immutable initial product schema.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/outbox.sql");

mod delta;
mod history;

mod memberships;

mod graph;

mod sources;

/// Cross-owner read access, installed after product roles exist.
pub const RELATIONS_SQL: &str = include_str!("../migrations/relations.sql");
/// Closed privileged functions exported to the product access role.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
