//! Deterministic direct publication decisions; adapters own authentication and atomic persistence.
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]
#![deny(missing_docs)]
mod fingerprint;
mod identity;
mod model;
mod transition;
pub use identity::{ActorId, Digest, PublicationId, PublicationKey, RequestId, TargetId};
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
    /// The record, publication or attempt does not match the current subject.
    #[error("record or publication identity mismatch")]
    IdentityMismatch,
    /// The requested CAS revision differs from the current aggregate revision.
    #[error("revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict {
        /// Revision supplied by the request.
        expected: u64,
        /// Current publication revision.
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
    /// Withdrawal forbids new retries, while observed facts remain recordable.
    #[error("publication is withdrawn")]
    PublicationClosed,
    /// Ordinary authorization cannot resubmit a confirmed NotApplied attempt.
    #[error("publication requires reconciliation")]
    ReconciliationRequired,
    /// A new backend report contradicts a previously recorded terminal result.
    #[error("external publication results conflict")]
    ResultConflict,
}
