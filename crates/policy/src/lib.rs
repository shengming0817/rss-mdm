//! Policy lifecycle and deterministic intent planning; no storage or dispatch.
//! Callers supply authenticated identities and complete snapshots. Persisting the
//! returned preconditions and intents atomically belongs to the product adapter.
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]
mod fingerprint;
mod lifecycle;
mod model;
mod plan;
pub use lifecycle::*;
pub use model::*;
pub use plan::*;
