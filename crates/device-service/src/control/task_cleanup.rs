//! Retirement waits for work owned outside Execution on the original fenced transaction.
use crate::control::transaction::Result;
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
#[derive(Default)]
pub struct Progress {
    pub pending: bool,
    pub unknown: Option<Uuid>,
    pub facts: Vec<Fact>,
}
pub trait TaskCleanup: Send + Sync {
    fn installations_removed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: Uuid,
        target: &'a crate::control::Target,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;
    fn remove_software_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: Uuid,
        target: &'a crate::control::Target,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        registrations: &'a [Uuid],
    ) -> Pin<Box<dyn Future<Output = Result<Progress>> + Send + 'a>>;
}
