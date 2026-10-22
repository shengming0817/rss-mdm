//! Product-owned endpoint associations. Registration never depends on this service.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (borrowed transaction ownership).
mod changes;
mod cursor;
pub mod lifecycle;
pub mod lifecycle_management;
mod model;
pub mod personnel;
pub mod planning;
mod presentation;
mod views;
pub use views::{ViewQuery, ViewRef};
mod identity;
pub use identity::Hardware;
mod read;
mod reconcile;
mod write;
pub use model::*;
use rss_mdm_audit_integration::AuditStore;
use rss_request_context::TenantId;
use std::sync::Arc;

pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
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
