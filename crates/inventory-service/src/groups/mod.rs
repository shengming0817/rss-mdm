//! Group mutation and immutable membership views; Flow supplies scheduling and references.
use crate::{Error, Failure, assets, operation::Operation, transaction::*};
use assets::Criteria;
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
mod model;
mod mutation;
pub mod pages;
pub use model::{GroupChange, GroupStart};
pub struct Groups {
    pub tenant: TenantId,
    pub groups: Arc<rss_mdm_group_postgres::GroupStore>,
    pub cursor_key: ring::hmac::Key,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub clock: Arc<dyn crate::clock::Clock>,
}
pub trait Flow: Send + Sync {
    fn task<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        target: &'a str,
    ) -> crate::tasks::Pending<'a, Value>;
    fn start<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        start: GroupStart,
    ) -> crate::tasks::Pending<'a, Value>;
    fn assert_unused<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
    ) -> crate::tasks::Pending<'a, ()>;
    fn changed<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        revision: u64,
    ) -> crate::tasks::Pending<'a, ()>;
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum GroupMissing {
    #[error("group not found")]
    Group,
    #[error("group rule not found")]
    Rule,
    #[error("device not found")]
    Device,
}
fn group_checked<T>(r: std::result::Result<T, rss_mdm_group_postgres::Rejection>) -> Result<T> {
    r.map_err(|e| match e {
        rss_mdm_group_postgres::Rejection::NotFound
        | rss_mdm_group_postgres::Rejection::Deleted => Error::Group(GroupMissing::Group).into(),
        rss_mdm_group_postgres::Rejection::CapacityExceeded => {
            Error::Unavailable(Failure::AssetObjectLimit).into()
        }
        rss_mdm_group_postgres::Rejection::PageBudgetExceeded => {
            Error::Unavailable(Failure::AssetBytesLimit).into()
        }
        rss_mdm_group_postgres::Rejection::InvalidInput => Error::Malformed.into(),
        _ => Error::Conflict.into(),
    })
}
async fn require_device(tx: &mut PgTransaction<'_>, id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 255 {
        return Err(Error::Malformed.into());
    }
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    if !tx
        .with_connection(move |c| Box::pin(crate::device::read::registered(c, tenant, id)))
        .await?
    {
        return Err(Error::Group(GroupMissing::Device).into());
    }
    Ok(())
}

pub mod directory;
mod receipts;
mod service;
pub use service::Command;

pub mod response;
