//! MDM facts and request settlement over the public Audit component.
#![forbid(unsafe_code)]

mod intent;
pub use intent::{AuditIntent, SensitiveAction};

pub use rss_mdm_install_support::StorageProfile;
pub mod command_transaction;
mod context;
pub mod operation;
mod settlement;
pub use context::{
    AuthenticationKind, FailureReason, ManagementResult, Origin, RequestAudit, Snapshot,
    SoftwareFact, TargetKind, WriteOutcome,
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
pub const LEDGER_ACCESS_CONTRACT: &str = include_str!("ledger-access-contract.json");

pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

#[cfg(unix)]
pub mod backup;

#[cfg(test)]
pub(crate) fn test_binding(tenant: &str) -> rss_transactional_messaging::fence::ExecutionBinding {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16]).unwrap(),
        rss_request_context::TenantId::parse(tenant).unwrap(),
        Epoch::new(1).unwrap(),
    )
}
