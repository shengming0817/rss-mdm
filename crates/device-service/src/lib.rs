//! Product-owned endpoint associations. Registration never depends on this service.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (borrowed transaction ownership).
pub mod association_directory;
pub mod changes;
mod cursor;
pub mod directory;
mod directory_filter;
pub mod lifecycle;
pub mod lifecycle_management;
mod model;
pub mod personnel;
pub mod planning;
mod presentation;
pub mod view_response;
mod views;
pub use views::ViewRef;
mod identity;
pub use identity::Hardware;
mod read;
mod reconcile;
mod write;
pub use model::*;
use rss_mdm_audit_integration::AuditStore;
use rss_request_context::TenantId;
use std::sync::Arc;

pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/install.sql"),
    "\n",
    include_str!("../schema/object-qualification.sql")
);
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

/// App-owned service, borrowing the existing Audit transaction owner.
pub struct Associations {
    audit: Arc<AuditStore>,
    tenant: TenantId,
    key: ring::hmac::Key,
}
impl Associations {
    pub fn new(audit: Arc<AuditStore>, tenant: TenantId, secret: &[u8]) -> Result<Self> {
        if secret.len() != 32 {
            return Err(Error::Malformed);
        }
        let secret = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
            b"device-associations-v1",
        );
        Ok(Self {
            audit,
            tenant,
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_ref()),
        })
    }
}

/// Product query revisions and narrow same-database read grants.
pub const DIRECTORY_SQL: &str = include_str!("../schema/directory.sql");

mod storage_authority;
pub use storage_authority::verify_authority;
