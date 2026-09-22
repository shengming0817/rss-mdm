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
pub use decisions::{
    DecisionOrigin, DecisionRecord, DecisionValue, FieldEvidence, PredicateDecision,
};
mod model;
pub use generations::{BuildRequest, DifferenceStep, MAX_MEMBERS, MemberBuild, MemberPatch};
mod storage;
mod store;
pub use event::EVENT_SCHEMA;
pub use model::*;
/// The same core types used in this adapter's signatures, available to one-package consumers.
pub use rss_mdm_group as core;
pub use store::GroupStore;
/// One-time owner migration; not executable by the runtime role. No legacy upgrade path.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_group.sql");
#[cfg(test)]
mod codec_tests;

/// Public Outbox function permissions, installed after the immutable initial product schema.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/0002_outbox_writer.sql");
/// Immutable paged member results and atomic current-set publication.
pub const GENERATIONS_MIGRATION_SQL: &str =
    include_str!("../migrations/0003_member_generations.sql");
