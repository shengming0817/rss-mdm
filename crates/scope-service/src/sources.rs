//! Frozen source inputs and consumer-owned participation ports for F03 (#3042).
//! Device facts continue to use Inventory's existing ObjectReader, implemented by Device.
use rss_mdm_group::{GroupId, GroupSource, Outcome};
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceSet {
    pub reference: Reference,
    pub coordinates: rss_mdm_group::SourceCoordinates,
    pub snapshot: Option<rss_mdm_inventory_service::objects::ObjectSnapshot>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeInput {
    pub definition: ScopeDefinition,
    pub sources: Vec<SourceSet>,
    pub as_of: i64,
}

/// Scope's dependency on immutable Group membership; no Group application service.
pub trait GroupMembershipReader: Send + Sync {
    type Error;
    /// Capture definition, member-result and authority coordinates under the owner lock.
    fn capture_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        group: GroupId,
    ) -> Pin<Box<dyn Future<Output = Result<GroupSource, Self::Error>> + Send + 'a>>;
    /// Read only this frozen result, retaining Unknown rather than treating it as false.
    /// The object page is bounded by rss_mdm_group::limits::OBJECTS.
    fn decisions_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        source: &'a GroupSource,
        objects: &'a [String],
    ) -> Pin<
        Box<
            dyn Future<Output = Result<std::collections::BTreeMap<String, Outcome>, Self::Error>>
                + Send
                + 'a,
        >,
    >;
}
/// Execution owns channel projection writes; Scope owns the result publication.
/// Both sides borrow this exact transaction. Failure must abort the whole publication.
pub trait ChannelProjectionPublisher: Send + Sync {
    type Error;
    /// Validate and publish the already staged channel projection for this exact run.
    /// No independent commit and no success for pending/incomplete projection are allowed.
    fn publish_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        publication: &'a rss_mdm_scope_postgres::Publication,
    ) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send + 'a>>;
}
