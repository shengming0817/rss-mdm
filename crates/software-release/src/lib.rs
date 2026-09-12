//! Deterministic software publication decisions, without storage or authentication.
//! Persist the next snapshot and request receipt atomically before executing a decision.
//! Restored inputs require a trusted storage owner; structural checks do not authenticate them.
//! Candidate identity cannot be replaced by a same-tenant actor:
//! ```compile_fail
//! use rss_mdm_software_release::{ActorId, Candidate, Content};
//! fn wrong_role(actor: ActorId, content: Content, at: rss_contract::Timepoint) {
//!     Candidate::new(actor, content, at);
//! }
//! ```
//! Snapshots must pass the aggregate's restore validation:
//! ```compile_fail
//! use rss_mdm_software_release::{Candidate, Snapshot};
//! fn bypass(snapshot: Snapshot) -> Candidate { Candidate(snapshot) }
//! ```
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]
mod fingerprint;
mod identity;
mod model;
mod transition;
pub use identity::{ActorId, CandidateId, Digest, PublicationId, RequestId};
pub use model::*;
pub use transition::*;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("invalid bounded identity")]
    InvalidIdentity,
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("invalid or conflicting artifact collection")]
    InvalidArtifacts,
    #[error("tenant mismatch")]
    TenantMismatch,
    #[error("candidate or publication identity mismatch")]
    IdentityMismatch,
    #[error("revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("revision or attempt overflow")]
    Overflow,
    #[error("request identity reused with different input")]
    RequestConflict,
    #[error("invalid restored snapshot or receipt")]
    InvalidSnapshot,
    #[error("time precedes existing facts or evidence is from the future")]
    InvalidTime,
    #[error("invalid lifecycle transition")]
    InvalidTransition,
    #[error("previous ring is not confirmed published")]
    PromotionBlocked,
    #[error("approved content cannot be changed after publication authorization")]
    ContentFrozen,
    #[error("candidate software identity cannot change")]
    ContentConflict,
    #[error("validation or approval does not match the current subject")]
    StaleEvidence,
    #[error("validation has not passed")]
    ValidationRequired,
    #[error("actor constraint is not satisfied")]
    ActorConstraint,
    #[error("candidate is withdrawn or deprecated")]
    PublicationClosed,
    #[error("publication requires reconciliation")]
    ReconciliationRequired,
    #[error("external publication results conflict")]
    ResultConflict,
}
