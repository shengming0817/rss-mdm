//! Dependencies of Policy publication, implemented by the appropriate owners in F06.
//! These are facts inside the initiating transaction, not independent service requests.
use rss_mdm_resource::{Id, State, Version};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

/// Policy requires its root and rollout stage definitions to remain undeleted.
/// This does not demand a newly computed result on every observation watermark.
pub trait ScopeTargetReader: Send + Sync {
    type Error;
    fn require_definitions_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scopes: &'a [Uuid],
    ) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send + 'a>>;
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
    ) -> Pin<Box<dyn Future<Output = Result<(Version, State), Self::Error>> + Send + 'a>>;
}
