//! Product software authority and external publication over existing RSS transactions.
//! Resource owns definitions; the host owns authenticated actors, secrets and composition.
#![deny(clippy::cognitive_complexity)]
pub mod management;
pub mod preparation;
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
    fn brew_read(
        &self,
        tenant: TenantId,
        source: &str,
        reference: &str,
    ) -> publication::Result<BrewReadAccess>;
}
/// A source-scoped read credential for the narrow Brew upload-pack/artifact surface.
/// Neither tokens nor their hashes are serialized into source definitions or documents.
pub struct BrewReadAccess {
    tenant: TenantId,
    source: String,
    digest: [u8; 32],
}
impl BrewReadAccess {
    pub fn new(tenant: TenantId, source: &str, token: &str) -> publication::Result<Self> {
        use sha2::{Digest, Sha256};
        rss_mdm_resource::Id::new(source).map_err(|_| publication::Error::Input)?;
        if token.len() < 32 || token.len() > 512 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(publication::Error::Input);
        }
        Ok(Self {
            tenant,
            source: source.into(),
            digest: Sha256::digest(token.as_bytes()).into(),
        })
    }
    pub fn permits(&self, tenant: TenantId, source: &str, token: &str) -> bool {
        use sha2::{Digest, Sha256};
        if tenant != self.tenant || source != self.source || token.len() > 512 {
            return false;
        }
        let digest = Sha256::digest(token.as_bytes());
        self.digest
            .iter()
            .zip(digest.iter())
            .fold(0u8, |sum, (a, b)| sum | (a ^ b))
            == 0
    }
}
pub struct Host {
    pub content: Arc<dyn catalog::ContentPort>,
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<dyn AuditPort>,
    pub credentials: Arc<dyn Credentials>,
}
pub mod catalog;
pub mod imports;

impl AuditPort for rss_mdm_audit_integration::AuditStore {
    fn lock_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> AuditFuture<'a> {
        Box::pin(async move { self.lock_in(tx).await })
    }
    fn append_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        fact: &'a Fact,
        replayed: bool,
    ) -> AuditFuture<'a> {
        Box::pin(async move { self.append_in(tx, fact, replayed).await })
    }
    fn append_request_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        request: &'a RequestAudit,
        status: u16,
        result: &'a str,
    ) -> AuditFuture<'a> {
        Box::pin(async move { self.append_request_in(tx, request, status, result).await })
    }
}
