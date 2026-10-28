//! Dependencies of Policy publication, implemented by the appropriate owners in F06.
//! These are facts inside the initiating transaction, not independent service requests.
use rss_mdm_resource::{Id, State, Version};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

/// One operation borrowing its initiating transaction.
pub type Pending<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Policy requires its root and rollout stage definitions to remain undeleted.
/// This does not demand a newly computed result on every observation watermark.
pub trait ScopeTargetReader: Send + Sync {
    type Error;
    fn require_definitions_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scopes: &'a [Uuid],
    ) -> Pending<'a, (), Self::Error>;
}
/// Lock and read exact immutable Resource material before creating a Policy reference.
/// All reference writers and archive checks use the same resource aggregate lock.
pub trait ResourceVersionReader: Send + Sync {
    type Error;
    fn lock_version_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        resource: &'a Id,
        version: &'a Id,
    ) -> Pending<'a, (Version, State), Self::Error>;
}

/// Closed failures from validation of exact profile material.
#[derive(Clone, Copy, Debug)]
pub enum ProfileValidationError {
    Invalid,
    Conflict,
    Unavailable,
}
/// Validates a locked template using Inventory facts and Telemetry rules.
pub trait ProfileValidator: Send + Sync {
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        template: &'a Version,
        profile: &'a rss_mdm_resource::TelemetryProfile,
    ) -> Pending<'a, Vec<rss_mdm_inventory::FieldDefinition>, ProfileValidationError>;
}
