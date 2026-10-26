//! MDM facts and request settlement over the public Audit component.
#![forbid(unsafe_code)]

mod intent;
pub use intent::{AuditIntent, SensitiveAction};

mod context;
pub use context::{
    AuthenticationKind, FailureReason, ManagementResult, RequestAudit, Snapshot, SoftwareFact,
    TargetKind, WriteOutcome,
};

mod fact;
pub use fact::{Fact, InvalidFact};

pub mod activity;

mod read_store;
pub use read_store::AuditReadStore;
mod source_transaction;
pub use source_transaction::{SourceTransaction, TransactionError};
mod store;
pub use store::{AuditStore, Error, ErrorClass};

pub mod budget;

pub mod completion;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub const OPERATION_RECEIPTS_SQL: &str = include_str!("operation-install.sql");
pub const OPERATION_RECEIPT_RELATIONS_SQL: &str = include_str!("operation-relations.sql");
pub mod operation_receipts;
