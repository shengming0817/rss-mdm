//! Host-owned principal/secret/audit implementation for the software service.
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_software_service::{AuditFuture, AuditPort};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub struct Audit(pub Arc<AuditStore>);
impl AuditPort for Audit {
    fn lock_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> AuditFuture<'a> {
        Box::pin(async move { self.0.lock_in(tx).await })
    }
    fn append_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        fact: &'a Fact,
        replayed: bool,
    ) -> AuditFuture<'a> {
        Box::pin(async move { self.0.append_in(tx, fact, replayed).await })
    }
    fn append_request_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        request: &'a RequestAudit,
        status: u16,
        result: &'a str,
    ) -> AuditFuture<'a> {
        Box::pin(async move { self.0.append_request_in(tx, request, status, result).await })
    }
}
