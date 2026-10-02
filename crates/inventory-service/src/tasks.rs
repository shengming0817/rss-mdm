use crate::{Error, assets, compliance};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobInput {
    Compliance {
        input: Box<compliance::Input>,
    },
    AssetQuery {
        query: Box<assets::Query>,
        scope: assets::ReadScope,
        watermark: i64,
        as_of: i64,
    },
}
pub type State = (JobInput, bool, Option<String>, Option<String>, bool);
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub trait Tasks: Send + Sync {
    fn enqueue<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        input: &'a JobInput,
    ) -> Pending<'a, serde_json::Value>;
    fn read<'a, 'tx>(&'a self, tx: &'a mut PgTransaction<'tx>, id: Uuid) -> Pending<'a, State>;
    fn finish<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        store: &'a rss_mdm_audit_integration::AuditStore,
        id: Uuid,
        failure: Option<&'a str>,
    ) -> Pending<'a, ()>;
    fn cursor<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        cursor: Option<String>,
    ) -> Pending<'a, ()>;
    fn detail<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
    ) -> Pending<'a, Option<serde_json::Value>>;
    fn set_detail<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        detail: serde_json::Value,
    ) -> Pending<'a, ()>;
}
pub fn asset_target(tenant: rss_request_context::TenantId) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.assets").expect("constant domain"),
        "changes",
    )
    .expect("constant target")
}

/// Stable task result shape consumed by Inventory and its scheduling participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
pub struct JobAccepted {
    pub task: Uuid,
    pub kind: String,
    pub target: String,
    pub status_url: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
pub struct TaskRead {
    pub task: Uuid,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub processed: u64,
    pub members: u64,
    pub failure: Option<String>,
    pub failure_detail: Option<serde_json::Value>,
    pub replacement_task: Option<Uuid>,
}
