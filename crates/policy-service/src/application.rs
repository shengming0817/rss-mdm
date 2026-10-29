//! Policy application context, with explicit transaction and audit participants.

pub(crate) use crate::{Error, Failure};

pub(crate) use rss_request_context::TenantId;
pub(crate) use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
pub(crate) use std::sync::Arc;
pub(crate) use uuid::Uuid;

pub struct Application {
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) automation_observation:
        std::sync::Mutex<crate::worker::health::AutomationObservation>,
    pub(crate) automation_task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    pub runtime: Arc<PgRuntime>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) cursor_key: ring::hmac::Key,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub tenant: TenantId,
    pub clock: Arc<dyn crate::clock::Clock>,
}
pub(crate) use crate::transaction::*;
impl Application {
    pub async fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        cursor_key: &[u8],
        objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    ) -> std::result::Result<Self, Error> {
        let reconcile_messaging =
            rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::PolicyAdmission))?;
        Ok(Self {
            audit_store: audit_store.clone(),
            automation_observation: std::sync::Mutex::new(Default::default()),
            automation_task: std::sync::OnceLock::new(),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
            objects,
            reconcile_messaging,
            runtime,
            tenant,
            clock,
        })
    }
}

pub(crate) use rss_mdm_audit_integration::RequestAudit;

impl Application {
    pub fn automation_state(&self) -> Option<rss_runtime::TaskState> {
        self.automation_task
            .get()
            .map(rss_runtime::TaskStatus::current)
    }
}

pub(crate) async fn admit_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    crate::storage::verify_contract(tx, crate::ADMISSION_SQL, Failure::PolicyAdmission).await
}
