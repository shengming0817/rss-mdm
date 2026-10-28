//! Resource application dependency contracts; full use cases move in F05 (#3044).
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};

/// Facts from every referencing owner, including immutable historical versions.
/// Caller holds the resource aggregate lock until its one transaction settles.
/// Implementations must not commit, start another transaction or omit withdrawn references.
pub trait UsageReader: Send + Sync {
    /// Preserve business rejection and storage failure for the initiating owner.
    type Error;
    /// Count Policy, publication, catalog approval and Profile references in this snapshot.
    fn count_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, Self::Error>> + Send + 'a>>;
}
