//! Product-owned endpoint associations. Registration never depends on this service.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (borrowed transaction ownership).
mod array_read;
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
mod snapshot;
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
#[cfg(feature = "integration")]
type ReadGate = (tokio::sync::oneshot::Sender<()>, Arc<tokio::sync::Notify>);

pub struct Associations {
    #[cfg(feature = "integration")]
    read_gate: std::sync::Mutex<Option<ReadGate>>,
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
            #[cfg(feature = "integration")]
            read_gate: Default::default(),
            audit,
            tenant,
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_ref()),
        })
    }
}

/// Product query revisions and narrow same-database read grants.
pub const DIRECTORY_SQL: &str = concat!(
    include_str!("../schema/directory.sql"),
    "\n",
    include_str!("../schema/read-world.sql")
);

mod storage_authority;
pub use storage_authority::verify_authority;

#[cfg(feature = "integration")]
impl Associations {
    pub fn pause_read_before_authority(
        &self,
    ) -> (tokio::sync::oneshot::Receiver<()>, Arc<tokio::sync::Notify>) {
        let (send, receive) = tokio::sync::oneshot::channel();
        let resume = Arc::new(tokio::sync::Notify::new());
        assert!(
            self.read_gate
                .lock()
                .expect("read gate")
                .replace((send, resume.clone()))
                .is_none()
        );
        (receive, resume)
    }
    pub(crate) async fn read_checkpoint(&self) -> Result<()> {
        let gate = self.read_gate.lock().expect("read gate").take();
        if let Some((send, resume)) = gate {
            let _ = send.send(());
            tokio::time::timeout(std::time::Duration::from_secs(5), resume.notified())
                .await
                .map_err(|_| Error::Deadline)?;
        }
        Ok(())
    }
}
