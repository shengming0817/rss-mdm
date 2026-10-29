//! Complete Group use cases, immutable membership views and durable calculation.
use crate::{Error, Failure, assets, operation::Operation, transaction::*};
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub mod criteria;
pub mod dependencies;
mod model;
mod mutation;
pub mod pages;
pub mod references;
pub use model::{DefinitionEdit, GroupChange, GroupStart, RequiredAuthority};
pub struct Dependencies {
    pub objects: Arc<dyn crate::objects::ObjectReader>,
    pub tenant: TenantId,
    pub groups: Arc<rss_mdm_group_postgres::GroupStore>,
    pub cursor_key: ring::hmac::Key,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub clock: Arc<dyn crate::clock::Clock>,
}
pub struct Groups {
    pub(crate) task_status: std::sync::OnceLock<rss_runtime::TaskStatus>,
    runner_health: std::sync::Mutex<health::RunnerObservation>,
    pub(crate) input_state: std::sync::atomic::AtomicU8,
    pub(crate) objects: Arc<dyn crate::objects::ObjectReader>,
    pub(crate) tenant: TenantId,
    pub(crate) groups: Arc<rss_mdm_group_postgres::GroupStore>,
    pub(crate) cursor_key: ring::hmac::Key,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) clock: Arc<dyn crate::clock::Clock>,
}
#[derive(Clone, Copy, Debug, thiserror::Error, serde::Serialize)]
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

/// Selection metadata is frozen alongside the core rule, in the same mutation transaction.
pub async fn condition_in(
    tx: &mut PgTransaction<'_>,
    tenant: TenantId,
    group: rss_mdm_group::GroupId,
    version: &str,
    rule: &rss_mdm_group_postgres::core::Rule,
) -> Result<criteria::Condition> {
    let tenant = tenant.to_string();
    let group = group.to_string();
    let version = version.to_owned();
    let body: String = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT selection::text FROM mdm_assets.group_selections WHERE tenant_id=$1::uuid AND group_id=$2::uuid AND rule_version=$3")
            .bind(tenant).bind(group).bind(version).fetch_one(c).await
    })).await?;
    let (selector, quantifier) = stored(serde_json::from_str(&body))?;
    let condition = assets::InventoryCondition {
        selector,
        quantifier,
        criteria: criteria::view(rule.view().criteria)?,
    };
    condition.validate()?;
    Ok(condition)
}

pub mod memberships;

impl Groups {
    async fn current_in(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
        let id = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        let source = group_checked(self.groups.capture_source_in(tx, id).await?)?;
        group_checked(self.groups.source_current_in(tx, &source).await?)
    }
}

mod evaluation;
pub mod tasks;

mod calculation;
impl Groups {
    fn asset_reader(&self) -> assets::planning::SnapshotReader {
        assets::planning::SnapshotReader {
            tenant: self.tenant,
        }
    }
}

mod sources;

impl Groups {
    async fn define_in(&self, tx: &mut PgTransaction<'_>, edit: DefinitionEdit) -> Result<Value> {
        json(
            &self
                .enqueue_task_in(
                    tx,
                    edit.change.operation_id,
                    &tasks::TaskInput::Definition {
                        edit: Box::new(edit),
                    },
                )
                .await?,
        )
    }
    async fn assert_unused_in(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
        let binding = rss_mdm_scope_postgres::ScopeBinding::new(self.runtime.clone(), self.tenant);
        let used = binding.group_used_in(tx, id).await.map_err(|e| match e {
            rss_mdm_scope_postgres::BindingError::Storage(e) => Fault::Storage(e),
            rss_mdm_scope_postgres::BindingError::TenantMismatch => Error::Forbidden.into(),
            rss_mdm_scope_postgres::BindingError::Missing
            | rss_mdm_scope_postgres::BindingError::Conflict
            | rss_mdm_scope_postgres::BindingError::Invalid => {
                Error::Unavailable(Failure::AssetsStorage).into()
            }
        })?;
        if used {
            return Err(Error::Conflict.into());
        }
        Ok(())
    }
}

mod reference_page;

mod definition;

pub mod runtime;

mod ingress;
mod relations;

impl Groups {
    pub async fn new(dependencies: Dependencies) -> std::result::Result<Self, Error> {
        let Dependencies {
            objects,
            tenant,
            groups,
            cursor_key,
            audit_store,
            runtime,
            reconcile_messaging,
            clock,
        } = dependencies;
        let service = Self {
            task_status: Default::default(),
            runner_health: Default::default(),
            input_state: Default::default(),
            objects,
            tenant,
            groups,
            cursor_key,
            audit_store,
            runtime,
            reconcile_messaging,
            clock,
        };
        let valid = service
            .runtime
            .local_tx_with_context(tenant, deadline(), &service, |s, tx| {
                Box::pin(async move {
                    if s.groups.graph_revision_in(tx).await?.is_err() {
                        return Ok(false);
                    }
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::AssetsStorage)),
                |_| Err(Error::Unavailable(Failure::AssetsStorage)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Conflict),
            )?;
        if !valid {
            return Err(Error::Unavailable(Failure::AssetsStorage));
        }
        Ok(service)
    }
}

impl Groups {
    async fn lock_business_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.check_task_transaction(tx)?;
        crate::transaction::lock(tx).await?;
        Ok(())
    }
}

pub mod health;
