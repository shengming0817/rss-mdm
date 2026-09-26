//! MDM facts and request settlement over the public Audit component.
#![forbid(unsafe_code)]
mod context;
pub use context::{
    FailureReason, ManagementResult, RequestAudit, Snapshot, SoftwareFact, WriteOutcome,
};

mod fact;
pub use fact::{Fact, InvalidFact};

mod operation;
pub use operation::OperationControl;
mod store;
pub use store::{AuditStore, Error};

/// Product receipt schema, installed by the separately provisioned MDM owner.
pub const MIGRATION_SQL: &str = include_str!("receipts.sql");
