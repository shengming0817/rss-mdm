//! MDM facts and request settlement over the public Audit component.
#![forbid(unsafe_code)]
mod context;
pub use context::{
    FailureReason, ManagementResult, RequestAudit, Snapshot, SoftwareFact, WriteOutcome,
};

mod fact;
pub use fact::{Fact, InvalidFact};

mod store;
pub use store::{AuditStore, Error};

/// Product receipt schema, installed by the separately provisioned MDM owner.
pub const MIGRATION_SQL: &str = include_str!("receipts.sql");

pub mod budget;

pub mod completion;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub const OPERATION_RECEIPTS_SQL: &str = include_str!("operation-install.sql");
pub const OPERATION_RECEIPT_RELATIONS_SQL: &str = include_str!("operation-relations.sql");
pub mod operation_receipts;
