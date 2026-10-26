//! One device activity projection over the original source-owned audit facts.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.9.0 (transaction-scoped publication).
mod access;
mod model;
mod projection;
mod query;
pub use model::{ACTIVITIES, Query, Reader};
pub(crate) use projection::{project_activity, publish_in};
