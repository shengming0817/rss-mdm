//! Closed persistent Policy definitions and deterministic schedule decisions.
//! Scope and Resource identities are opaque references. This core owns no target
//! enumeration, authorization, execution fact, database, HTTP or device protocol.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
mod assignment;
mod model;
/// Calendar, window and late-checkin decisions over an explicit clock value.
pub mod schedule;
pub use assignment::*;
pub use model::*;
/// A malformed definition or a failed configuration CAS.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A definition violates its closed shape or bounds.
    #[error("invalid Policy input")]
    Malformed,
    /// Expected configuration revision no longer matches.
    #[error("Policy revision conflict")]
    Conflict,
    /// Enable or disable refers to an absent policy.
    #[error("Policy not found")]
    NotFound,
}
