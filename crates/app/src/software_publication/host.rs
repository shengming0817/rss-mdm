//! Host-owned principal/secret/audit implementation for the software service.
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_software_service::{AuditFuture, AuditPort, Credentials};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
pub(crate) struct Audit(pub Arc<AuditStore>);
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
pub(crate) struct SourceCredentials {
    tenant: rss_request_context::TenantId,
    source: String,
    values: BTreeMap<String, zeroize::Zeroizing<String>>,
}
impl SourceCredentials {
    pub(crate) fn load(
        tenant: rss_request_context::TenantId,
        source: &str,
        files: &BTreeMap<String, PathBuf>,
    ) -> Result<Self, crate::Error> {
        let mut values = BTreeMap::new();
        for (key, path) in files {
            values.insert(key.clone(), crate::config::secret(path)?);
        }
        Ok(Self {
            tenant,
            source: source.into(),
            values,
        })
    }
}
impl Credentials for SourceCredentials {
    fn winget(
        &self,
        tenant: rss_request_context::TenantId,
        source: &str,
        reference: &str,
    ) -> rss_mdm_software_service::publication::Result<rss_mdm_winget_source::WriteAccess> {
        use rss_mdm_software_service::publication::Error;
        if tenant != self.tenant || source != self.source {
            return Err(Error::Identity);
        }
        rss_mdm_winget_source::WriteAccess::new(
            tenant,
            source,
            reference,
            self.values.get(reference).ok_or(Error::Identity)?,
        )
        .map_err(|_| Error::Identity)
    }
}
