//! Product planning composition. Core decisions and component storage retain their owners.
use crate::assets;
pub mod automation;

pub mod events;
pub mod policies;
pub mod references;

pub mod storage;

use crate::{Error, Failure};

use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub struct Planning {
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    automation_observation: std::sync::Mutex<automation::health::AutomationObservation>,
    pub(crate) automation_task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    pub runtime: Arc<PgRuntime>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    cursor_key: ring::hmac::Key,
    pub asset_reader: assets::planning::SnapshotReader,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub tenant: TenantId,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub groups: Arc<rss_mdm_group_postgres::GroupStore>,
}
use crate::transaction::*;
impl Planning {
    pub async fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        cursor_key: &[u8],
        objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    ) -> std::result::Result<Self, Error> {
        let groups = rss_mdm_group_postgres::GroupStore::new(runtime.clone(), tenant, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::PlanningAdmission))?;
        let reconcile_messaging =
            rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::PlanningAdmission))?;
        Ok(Self {
            audit_store: audit_store.clone(),
            automation_observation: std::sync::Mutex::new(Default::default()),
            automation_task: std::sync::OnceLock::new(),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
            asset_reader: assets::planning::SnapshotReader { tenant },
            objects,
            reconcile_messaging,
            runtime,
            tenant,
            clock,
            groups: Arc::new(groups),
        })
    }
}

use rss_mdm_audit_integration::RequestAudit;

pub mod error;

impl Planning {
    pub fn automation_state(&self) -> Option<rss_runtime::TaskState> {
        self.automation_task
            .get()
            .map(rss_runtime::TaskStatus::current)
    }
}

pub const ADMISSION_SQL: &str = include_str!("admission.sql");

pub(crate) async fn admit_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    crate::storage::verify_contract(tx, ADMISSION_SQL, Failure::PlanningAdmission).await?;
    crate::storage::verify_contract(
        tx,
        crate::automation::ADMISSION_SQL,
        Failure::AutomationAdmission,
    )
    .await
}
