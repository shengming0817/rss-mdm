//! Frozen source inputs and transaction-borrowing participation ports.
//! Device facts continue to use Inventory's existing ObjectReader, implemented by Device.
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};

/// One operation borrowing its initiating transaction.
pub type Pending<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;
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

/// Execution owns staging, progress and channel revisions. Scope owns the active run.
pub trait ChannelProjectionPublisher: Send + Sync {
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        publication: &'a rss_mdm_scope_postgres::Publication,
    ) -> Pending<'a, bool, crate::transaction::Fault>;
    fn publish_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        publication: &'a rss_mdm_scope_postgres::Publication,
    ) -> Pending<'a, bool, crate::transaction::Fault>;
    fn result_devices_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        scope: uuid::Uuid,
        run: uuid::Uuid,
        channel: rss_mdm_inventory::Channel,
        after: Option<&'a str>,
        limit: usize,
    ) -> Pending<'a, ResultDevices, crate::transaction::Fault>;
    fn result_detail_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        scope: uuid::Uuid,
        run: uuid::Uuid,
        channel: rss_mdm_inventory::Channel,
        device: &'a str,
    ) -> Pending<'a, ResultDetail, crate::transaction::Fault>;
}
pub struct ResultDevices {
    pub result: uuid::Uuid,
    pub devices: Vec<String>,
    pub current: bool,
}
pub struct ResultDetail {
    pub matched: bool,
    pub pending: bool,
    pub entry: i64,
    pub explanation: Option<rss_mdm_scope::MemberExplanation>,
}
/// The downstream owner checks references and accepts one durable publication notification.
/// It owns fan-out, retries and completion; Scope never receives its pagination cursor.
pub trait ScopeDependents: Send + Sync {
    fn used_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: uuid::Uuid,
    ) -> Pending<'a, bool, crate::transaction::Fault>;
    fn publication_recorded_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: uuid::Uuid,
        run: uuid::Uuid,
    ) -> Pending<'a, (), crate::transaction::Fault>;
}
