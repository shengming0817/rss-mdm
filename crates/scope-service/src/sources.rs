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

pub struct ResultPage<'a> {
    pub tenant: rss_request_context::TenantId,
    pub scope: uuid::Uuid,
    pub run: uuid::Uuid,
    pub channel: rss_mdm_inventory::Channel,
    pub after: Option<&'a str>,
    pub limit: usize,
}
pub struct ResultDevices {
    pub result: uuid::Uuid,
    pub devices: Vec<String>,
    pub current: bool,
}
pub struct ResultMember<'a> {
    pub tenant: rss_request_context::TenantId,
    pub scope: uuid::Uuid,
    pub run: uuid::Uuid,
    pub channel: rss_mdm_inventory::Channel,
    pub device: &'a str,
    pub objects: &'a dyn rss_mdm_inventory_service::objects::ObjectReader,
}
pub struct ResultDetail {
    pub available: bool,
    pub matched: bool,
    pub pending: bool,
    pub entry: i64,
    pub explanation: Option<rss_mdm_scope::MemberExplanation>,
}
/// Record the owning Policy's reconciliation in the publication transaction.
pub trait ScopeDependents: Send + Sync {
    fn publication_recorded_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        owner: rss_mdm_scope_postgres::ScopeOwner,
        run: uuid::Uuid,
    ) -> Pending<'a, (), crate::transaction::Fault>;
}
