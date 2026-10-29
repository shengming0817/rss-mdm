//! Remaining Execution source-change coordination.
pub mod clock;
mod diagnostic;
mod error;
mod error_projection;
pub mod operation;
pub mod source_work;
pub mod transaction;
pub mod worker_wake;
pub use diagnostic::Failure;
pub use error::Error;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

/// Remaining source/access facts, independent of Policy publication ownership.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
pub const ACCESS_ADMISSION_SQL: &str = include_str!("access-admission.sql");
