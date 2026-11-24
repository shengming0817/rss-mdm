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
pub use presentation::Presentation;
mod model;
pub use generations::{BuildRequest, DifferenceStep, MemberBuild, MemberPatch};
pub mod directory;
mod storage;
mod store;
pub use event::{EVENT_SCHEMA, GroupChangeKind, GroupChanged};
pub use model::*;
pub use store::GroupStore;
mod source_reader;
pub use source_reader::GroupSources;
/// One-time owner migration; not executable by the runtime role. No legacy upgrade path.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");
#[cfg(test)]
mod codec_tests;

/// Public Outbox function permissions, installed after the immutable initial product schema.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/outbox.sql");

mod delta;
mod history;

mod memberships;
pub use memberships::published_endpoint_member_on;

mod graph;

pub mod sources;

/// Cross-owner read access, installed after product roles exist.
pub const RELATIONS_SQL: &str = include_str!("../migrations/relations.sql");
/// Closed privileged functions exported to the product access role.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

/// Narrow Group facts and fences used by Scope installations.
pub const SCOPE_FACTS_SQL: &str = include_str!("../migrations/scope-facts.sql");

mod source_decisions;
/// Bounded frozen evidence and the actual bytes reserved before decoding.
pub struct DecisionPage {
    /// Ordered records; an empty page proves source enumeration has ended.
    pub items: Vec<DecisionRecord>,
    /// Accumulated evidence bytes, including per-record overhead.
    pub bytes: usize,
}
/// Selected frozen membership, with absent dynamic keys remaining unknown.
pub struct SourceDecisions {
    /// Explicit outcomes for the requested keys that have evidence.
    pub outcomes: std::collections::BTreeMap<rss_mdm_agent_wire::ObjectRef, rss_mdm_group::Outcome>,
    /// Accumulated evidence bytes, including per-record overhead.
    pub bytes: usize,
}
