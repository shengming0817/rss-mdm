//! Retirement consumes configuration cleanup without owning configuration state.
use crate::control::transaction::Result;
use rss_mdm_audit_integration::RequestAudit;
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub struct Progress {
    pub pending: bool,
    pub blocker: Option<(i32, Option<Uuid>)>,
}
pub trait ConfigurationCleanup: Send + Sync {
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: Uuid,
        device: &'a str,
        audit: &'a RequestAudit,
    ) -> Pin<Box<dyn Future<Output = Result<Progress>> + Send + 'a>>;
}
