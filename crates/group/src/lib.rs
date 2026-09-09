//! Pure, tenant-scoped Group rules. Preview and recalculation share one evaluator.
//! No legacy expression/JSON/SQL interpreter, group references, I/O or system clock.
//! Snapshot completeness and authorization are caller assertions, not authentication.
//!
//! ```
//! use rss_mdm_group::{diff, ObjectKey};
//! use rss_request_context::TenantId;
//! let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111")?;
//! let device = ObjectKey::new(tenant, "device-1")?;
//! let change = diff(tenant, &[], std::slice::from_ref(&device))?;
//! assert_eq!(change.added, vec![device]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
mod evaluation;
mod model;
mod rule;
pub use evaluation::{
    Decision, Evaluation, Explanation, ObjectEvaluation, Outcome, Provenance, Recalculation,
    UnknownReason,
};
pub use model::*;
pub use rule::{Criteria, Rule};

/// Closed diagnostics never contain fact values or caller-supplied strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIdentity,
    InvalidStructure,
    UnknownField,
    InvalidType,
    InvalidUnit,
    InvalidOperation,
    PermissionDenied,
    InvalidTime,
    TenantMismatch,
    IncompleteSnapshot,
    VersionMismatch,
    ConflictingObject,
    LimitExceeded,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "group input rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Fixed V1 input/work budgets; exceeding a budget never truncates output.
pub mod limits {
    pub const DEPTH: usize = 16;
    pub const NODES: usize = 256;
    pub const FIELDS: usize = 128;
    pub const SET_ITEMS: usize = 256;
    pub const STRING_BYTES: usize = 4096;
    pub const RULE_BYTES: usize = 64 * 1024;
    pub const OBJECTS: usize = 10_000;
    pub const BATCH_BYTES: usize = 16 * 1024 * 1024;
    pub const VISITS: usize = 1_000_000;
}
pub(crate) fn bound(n: usize, max: usize) -> Result<()> {
    if n > max {
        Err(Error::LimitExceeded)
    } else {
        Ok(())
    }
}
pub(crate) fn text(s: &str, total: &mut usize) -> Result<()> {
    bound(s.len(), limits::STRING_BYTES)?;
    *total = total.checked_add(s.len()).ok_or(Error::LimitExceeded)?;
    Ok(())
}
pub(crate) fn identity(s: &str, total: &mut usize) -> Result<()> {
    text(s, total)?;
    if s.trim().is_empty() || s.chars().any(char::is_control) {
        return Err(Error::InvalidIdentity);
    }
    Ok(())
}
