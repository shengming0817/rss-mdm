//! Authored action plans: frozen intent, approval and cancellation.
pub(crate) mod model;
pub(crate) mod schedule;
pub(crate) mod service;
pub(crate) mod storage;
use crate::execution_transaction::Result;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::{future::Future, pin::Pin, sync::Arc};
pub(crate) trait ActionDispatch: Send + Sync {
    fn target(&self, id: uuid::Uuid) -> rss_reconcile::Target;
    fn admit_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    fn initialize_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        id: uuid::Uuid,
        now: i64,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    fn manual_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        plan: &'a storage::Plan,
        now: i64,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;
}
pub(crate) struct ActionPlans {
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) content: Option<Arc<dyn crate::task_content::ContentPort>>,
    pub(crate) dispatch: Arc<dyn ActionDispatch>,
}

mod targets;

pub(crate) mod http;
