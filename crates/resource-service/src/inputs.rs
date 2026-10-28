//! Transaction-borrowing facts required by Resource authoring.
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
    ) -> Pin<Box<dyn Future<Output = std::result::Result<u64, Self::Error>> + Send + 'a>>;
}

use crate::transaction::Result;
use rss_mdm_resource::{TelemetryProfile, Version};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
/// Inventory owns the catalog fence and validates mapping and projection budgets.
pub trait CollectionValidator: Send + Sync {
    fn fence_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> Pending<'a, ()>;
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        version: &'a Version,
    ) -> Pending<'a, ()>;
}
/// Telemetry owns profile rules; the Resource owner supplies locked immutable material.
pub trait TelemetryProfileValidator: Send + Sync {
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        template: &'a Version,
        profile: &'a TelemetryProfile,
    ) -> Pending<'a, ()>;
}
/// Software owns catalog source, material and dependency admission.
pub trait SoftwareAuthoringValidator: Send + Sync {
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        version: &'a Version,
    ) -> Pending<'a, ()>;
}
