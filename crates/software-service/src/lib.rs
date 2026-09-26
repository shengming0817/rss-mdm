//! Product software authority and external publication over existing RSS transactions.
//! Resource owns definitions; the host owns authenticated actors, secrets and composition.
#![deny(clippy::cognitive_complexity)]
pub mod publication;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::{future::Future, pin::Pin, sync::Arc};
pub type AuditFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), rss_mdm_audit_integration::Error>> + Send + 'a>>;
/// Host audit participates in the exact borrowed transaction; never an asynchronous notification.
pub trait AuditPort: Send + Sync {
    fn lock_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> AuditFuture<'a>;
    fn append_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        fact: &'a Fact,
        replayed: bool,
    ) -> AuditFuture<'a>;
    fn append_request_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        request: &'a RequestAudit,
        status: u16,
        result: &'a str,
    ) -> AuditFuture<'a>;
}
/// Resolves only a host-approved exact credential binding, without exposing credential files.
pub trait Credentials: Send + Sync {
    fn winget(
        &self,
        tenant: TenantId,
        source: &str,
        reference: &str,
    ) -> publication::Result<rss_mdm_winget_source::WriteAccess>;
}
pub struct Host {
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<dyn AuditPort>,
    pub credentials: Arc<dyn Credentials>,
}
pub mod catalog;
