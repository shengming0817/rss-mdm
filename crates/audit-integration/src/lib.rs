//! MDM facts and request settlement over the public Audit component.
#![forbid(unsafe_code)]
mod context;
pub use context::{
    AuthenticationKind, FailureReason, ManagementResult, RequestAudit, Snapshot, SoftwareFact,
    TargetKind, WriteOutcome,
};

mod fact;
pub use fact::{Fact, InvalidFact};

mod backlog;
pub use backlog::BacklogSnapshot;
mod projection;
pub use projection::{AuditProjection, AuditProjectionError, AuditProjectionReport};
mod queue;
pub use queue::BacklogLimits;
mod read_store;
pub use read_store::AuditReadStore;
mod source;
mod source_transaction;
pub use source_transaction::{SourceTransaction, TransactionError};
mod store;
pub use store::{AuditStore, Error, ErrorClass};

/// Product receipt schema, installed by the separately provisioned MDM owner.
pub const MIGRATION_SQL: &str = include_str!("receipts.sql");

pub mod budget;

pub mod completion;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub const OPERATION_RECEIPTS_SQL: &str = include_str!("operation-install.sql");
pub const OPERATION_RECEIPT_RELATIONS_SQL: &str = include_str!("operation-relations.sql");
pub mod operation_receipts;

/// Declare an MDM fact's resource ordering alongside other ordered messages in the same transaction.
/// This declares no effect and grants no producer authority; the bound writer validates append provenance.
pub fn source_partition(
    tenant: rss_request_context::TenantId,
    kind: &str,
    resource: &str,
) -> Result<rss_transactional_messaging::message::PartitionIdentity, Error> {
    rss_audit_core::ResourceKind::parse(kind).map_err(|_| Error::Fact(InvalidFact::Resource))?;
    rss_audit_core::ResourceId::parse(resource).map_err(|_| Error::Fact(InvalidFact::Resource))?;
    source::partition(tenant, kind, resource)
}

/// Decode an authored source fact without projecting it or inventing a sink timestamp.
pub fn decode_source_event(bytes: &[u8]) -> Result<rss_audit_core::AuditEventV1, Error> {
    source::FrozenFact::decode(bytes)?.event()
}
