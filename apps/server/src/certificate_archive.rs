//! App-owned resource assembly; archive passwords are never startup configuration.
use rss_mdm_certificate_archive_service::{Archive, Clock, Error};
use std::sync::Arc;
pub(crate) struct ArchiveClock(pub Arc<dyn crate::clock::Clock>);
impl Clock for ArchiveClock {
    fn unix_seconds(&self) -> Result<i64, Error> {
        self.0.unix_seconds().map_err(|_| Error::Storage)
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete product monotonic clock provider"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
pub(crate) fn assemble(
    database: &crate::Database,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    clock: Arc<dyn crate::clock::Clock>,
) -> Arc<Archive> {
    Arc::new(Archive::new(
        database.archive_pool(),
        audit,
        Arc::new(ArchiveClock(clock)),
    ))
}
