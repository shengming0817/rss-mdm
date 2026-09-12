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
//! A pending attempt is state, not a report from the backend:
//! ```compile_fail
//! use rss_mdm_software_release::{Operation, PublicationId, PublicationOutcome, Ring};
//! fn pending(id: PublicationId) -> Operation {
//!     Operation::Record { ring: Ring::Test, publication: id, attempt: 1,
//!                         outcome: PublicationOutcome::Pending }
//! }
//! ```
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]
#![warn(missing_docs)]
mod fingerprint;
mod identity;
mod model;
mod transition;
pub use identity::{ActorId, CandidateId, Digest, PublicationId, RequestId};
pub use model::*;
pub use transition::*;

/// Stable rejection categories from construction, restore and lifecycle transitions.
/// Display text excludes actor keys and backend evidence contents.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A role key, software identity field or artifact key violates the bounded syntax.
    #[error("invalid bounded identity")]
    InvalidIdentity,
    /// A digest is not exactly 64 ASCII hexadecimal characters.
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    /// The artifact set is empty, too large or contains duplicate keys.
    #[error("invalid or conflicting artifact collection")]
    InvalidArtifacts,
    /// A request, actor or evidence record belongs to another tenant.
    #[error("tenant mismatch")]
    TenantMismatch,
    /// The candidate, ring, publication or attempt does not match the current subject.
    #[error("candidate or publication identity mismatch")]
    IdentityMismatch,
    /// The requested CAS revision differs from the current aggregate revision.
    #[error("revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict {
        /// Revision supplied by the request.
        expected: u64,
        /// Current candidate revision.
        actual: u64,
    },
    /// Incrementing a revision or attempt would exceed its numeric range.
    #[error("revision or attempt overflow")]
    Overflow,
    /// An idempotency key or receipt was reused with different original inputs.
    #[error("request identity reused with different input")]
    RequestConflict,
    /// A restored snapshot or replay receipt is structurally inconsistent.
    #[error("invalid restored snapshot or receipt")]
    InvalidSnapshot,
    /// A request/evidence time precedes required facts or lies in the future.
    #[error("time precedes existing facts or evidence is from the future")]
    InvalidTime,
    /// The requested lifecycle edge is not supported.
    #[error("invalid lifecycle transition")]
    InvalidTransition,
    /// The previous ring has no confirmed Applied publication.
    #[error("previous ring is not confirmed published")]
    PromotionBlocked,
    /// A publication attempt prevents content replacement or revalidation.
    #[error("approved content cannot be changed after publication authorization")]
    ContentFrozen,
    /// Replacement would change the candidate’s exact software identity.
    #[error("candidate software identity cannot change")]
    ContentConflict,
    /// Validation, approval or predecessor binding differs from current content/state.
    #[error("validation or approval does not match the current subject")]
    StaleEvidence,
    /// Current passed validation or a usable approval is absent.
    #[error("validation has not passed")]
    ValidationRequired,
    /// Publisher identity or the declared publisher/approver separation is violated.
    #[error("actor constraint is not satisfied")]
    ActorConstraint,
    /// Quarantine or deprecation forbids a new validation, approval, authorization or retry.
    #[error("candidate is withdrawn or deprecated")]
    PublicationClosed,
    /// Ordinary authorization cannot resubmit a confirmed NotApplied attempt.
    #[error("publication requires reconciliation")]
    ReconciliationRequired,
    /// A new backend report contradicts a previously recorded terminal result.
    #[error("external publication results conflict")]
    ResultConflict,
}
