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
pub mod object_changed;
pub mod personnel;
pub mod planning;
mod presentation;
mod snapshot;
pub mod view_response;
mod views;
use rss_mdm_agent_wire::ObjectRef;
mod identity;
pub use identity::Hardware;
mod identity_projection;
mod read;
pub use read::ReceiptNamespace;
mod reconcile;
pub mod worker;
mod write;
pub use model::*;
use rss_mdm_audit_integration::AuditStore;
use rss_request_context::TenantId;
use std::sync::Arc;

pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/install.sql"),
    "\n",
    include_str!("../schema/identity.sql"),
    "\n",
    include_str!("../schema/object-qualification.sql"),
    "\n",
    include_str!("../schema/object-changes.sql")
);
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub struct Associations {
    worker_observed: std::sync::atomic::AtomicBool,
    worker_status: std::sync::OnceLock<rss_runtime::TaskStatus>,
    worker_failures: std::sync::Mutex<std::collections::BTreeMap<String, rss_reconcile::ErrorKind>>,
    audit: Arc<AuditStore>,
    tenant: TenantId,
    key: ring::hmac::Key,
}
pub struct WorkerHealth {
    pub task: Option<rss_runtime::TaskState>,
    pub observed: bool,
    pub unresolved_attempts: u64,
    pub truncated: bool,
    pub failure: Option<rss_reconcile::ErrorKind>,
}
impl Associations {
    pub fn worker_health(&self) -> WorkerHealth {
        let (unresolved_attempts, truncated, failure) = self
            .worker_failures
            .lock()
            .map(|failures| {
                (
                    failures.keys().filter(|key| !key.starts_with('!')).count() as u64,
                    failures.contains_key("!truncated"),
                    failures.values().next().copied(),
                )
            })
            .unwrap_or((0, true, Some(rss_reconcile::ErrorKind::Invariant)));
        WorkerHealth {
            task: self
                .worker_status
                .get()
                .map(rss_runtime::TaskStatus::current),
            observed: self
                .worker_observed
                .load(std::sync::atomic::Ordering::Acquire),
            unresolved_attempts,
            truncated,
            failure,
        }
    }
    pub fn worker_ready(&self) -> bool {
        let health = self.worker_health();
        health.observed
            && health.task == Some(rss_runtime::TaskState::Running)
            && health.failure.is_none()
    }
    pub fn new(audit: Arc<AuditStore>, tenant: TenantId, secret: &[u8]) -> Result<Self> {
        if secret.len() != 32 {
            return Err(Error::Malformed);
        }
        let secret = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
            b"device-associations-v1",
        );
        Ok(Self {
            worker_observed: Default::default(),
            worker_status: Default::default(),
            worker_failures: Default::default(),
            audit,
            tenant,
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_ref()),
        })
    }
}

/// Narrow same-database identity read grants.
pub const DIRECTORY_SQL: &str = concat!(
    include_str!("../schema/directory.sql"),
    "\n",
    include_str!("../schema/read-world.sql")
);

mod storage_authority;
pub use storage_authority::verify_authority;

/// Fixed device controls and management retirement.
pub mod control;

/// Product identity validation at native relational boundaries.
pub(crate) fn device_id(
    id: uuid::Uuid,
) -> std::result::Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}
pub(crate) fn device_ids(
    ids: Vec<uuid::Uuid>,
) -> std::result::Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    ids.into_iter().map(device_id).collect()
}
