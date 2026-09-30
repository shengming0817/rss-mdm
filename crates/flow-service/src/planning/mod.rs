//! Product planning composition. Core decisions and component storage retain their owners.
use crate::assets;
pub mod automation;

pub mod configuration;

pub mod directory;
pub mod model;
pub mod pages;
pub mod policies;
pub mod references;
pub mod remote_operations;

mod scopes;
pub mod sources;
pub mod storage;

pub mod wire;
use crate::{Error, Failure};

pub use model::Permission;
pub use model::*;
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub struct Planning {
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    automation_observation: std::sync::Mutex<automation::health::AutomationObservation>,
    pub automation_task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    pub runtime: Arc<PgRuntime>,
    cursor_key: ring::hmac::Key,
    pub asset_reader: assets::planning::SnapshotReader,
    pub tenant: TenantId,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub groups: Arc<rss_mdm_group_postgres::GroupStore>,
    sources: sources::SourceHeads,
    pub policy_store: rss_mdm_policy_postgres::PolicyStore,
    pub catalog: Arc<crate::resource_catalog::ResourceCatalog>,
}
use crate::operation::Operation;
use crate::transaction::*;
impl Planning {
    pub async fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        catalog: Arc<crate::resource_catalog::ResourceCatalog>,
        cursor_key: &[u8],
    ) -> std::result::Result<Self, Error> {
        let groups = rss_mdm_group_postgres::GroupStore::new(runtime.clone(), tenant, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::PlanningAdmission))?;
        let policy_store =
            rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::PlanningAdmission))?;
        Ok(Self {
            audit_store: audit_store.clone(),
            automation_observation: std::sync::Mutex::new(Default::default()),
            automation_task: std::sync::OnceLock::new(),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
            asset_reader: assets::planning::SnapshotReader { tenant },
            runtime,
            tenant,
            clock,
            groups: Arc::new(groups),
            sources: sources::SourceHeads::new(tenant),
            policy_store,
            catalog,
        })
    }
    // Business rejection must roll back already executed companion steps. Keep its
    // closed category separately; PgError deliberately redacts provider error sources.
    pub async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> std::result::Result<Value, Error> {
        let group = match command {
            Command::Group { id, change } => {
                Some(rss_mdm_inventory_service::groups::Command::Group {
                    id: *id,
                    change: rss_mdm_inventory_service::operation::Operation {
                        operation_id: change.operation_id,
                        expected_revision: change.expected_revision,
                        input: change.input.clone(),
                    },
                })
            }
            Command::GroupRead { id } => {
                Some(rss_mdm_inventory_service::groups::Command::GroupRead { id: *id })
            }
            Command::GroupPreview {
                id,
                operation,
                expected_revision,
            } => Some(rss_mdm_inventory_service::groups::Command::GroupPreview {
                id: *id,
                operation: *operation,
                expected_revision: *expected_revision,
            }),
            Command::GroupPage {
                group,
                result,
                projection,
                query,
            } => Some(rss_mdm_inventory_service::groups::Command::GroupPage {
                group: *group,
                result: *result,
                projection: *projection,
                query: rss_mdm_inventory_service::groups::pages::PageQuery {
                    limit: query.limit,
                    cursor: query.cursor.clone(),
                },
            }),
            Command::TaskRead {
                id,
                target,
                family: crate::automation::TaskKind::Group,
            } => Some(rss_mdm_inventory_service::groups::Command::TaskRead {
                id: *id,
                target: target.clone(),
            }),
            _ => None,
        };
        if let Some(group) = group {
            return self
                .inventory_groups()
                .execute(
                    &group,
                    audit,
                    &|| {
                        authorize()
                            .map_err(|e| crate::automation::inventory_tasks::failure(e.into()))
                    },
                    self,
                )
                .await
                .map_err(Error::from);
        }
        authorize()?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            &(self, command, audit, authorize),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, authorize) = *ctx;
                    let partitions = match command {
                        Command::Group { id, .. } => vec![s.groups.partition(&id.to_string())?],
                        _ => Vec::new(),
                    };
                    tx.prepare_outbox_partitions(&partitions).await?;
                    s.execute_in(tx, command, audit, authorize).await
                })
            },
            crate::transaction::TransactionOwner::Planning,
        )
        .await
    }
    async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> Result<Value> {
        crate::transaction::lock(tx).await?;
        authorize()?;
        let (operation, fingerprint) = storage::identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) =
                crate::planning::receipts::replay(tx, audit, id, &fingerprint).await?
        {
            wire::Response::decode(old.clone())?;
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            crate::planning::receipts::audit(
                tx,
                &self.audit_store,
                audit,
                operation.zip(Some(fingerprint.as_slice())),
                true,
            )
            .await?;
            authorize()?;
            return Ok(old);
        }
        let at = self
            .clock
            .unix_seconds()
            .map_err(|_| Error::Unavailable(Failure::Clock))?;
        let value = self
            .dispatch(tx, command, checked_input(Timepoint::try_from(at))?)
            .await?;
        // Reject a projection/schema defect before any mutation can commit.
        wire::Response::decode(value.clone())?;
        if let Some(id) = operation {
            crate::planning::receipts::receipt(tx, audit, id, &fingerprint, &value).await?;
        }
        crate::planning::receipts::audit(
            tx,
            &self.audit_store,
            audit,
            operation.zip(Some(fingerprint.as_slice())),
            false,
        )
        .await?;
        authorize()?;
        Ok(value)
    }
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat exhaustive command routing keeps the public operation set auditable"
    )]
    async fn dispatch(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        at: Timepoint,
    ) -> Result<Value> {
        match command {
            Command::Group { id, change } => self
                .inventory_groups()
                .group_change(
                    tx,
                    *id,
                    &rss_mdm_inventory_service::operation::Operation {
                        operation_id: change.operation_id,
                        expected_revision: change.expected_revision,
                        input: change.input.clone(),
                    },
                    at,
                    self,
                )
                .await
                .map_err(Into::into),
            Command::GroupRead { id } => self
                .inventory_groups()
                .group_read(tx, *id)
                .await
                .map_err(Into::into),
            Command::GroupPreview {
                id,
                operation,
                expected_revision,
            } => self
                .inventory_groups()
                .group_preview(tx, *id, *operation, *expected_revision, at, self)
                .await
                .map_err(Into::into),
            Command::Scope { id, change } => self.scope_change(tx, *id, change, at).await,
            Command::ScopeRead { id } => self.scope_read(tx, *id).await,
            Command::GroupPage {
                group,
                result,
                projection,
                query,
            } => self
                .inventory_groups()
                .group_page_in(
                    tx,
                    *group,
                    *result,
                    *projection,
                    &rss_mdm_inventory_service::groups::pages::PageQuery {
                        limit: query.limit,
                        cursor: query.cursor.clone(),
                    },
                )
                .await
                .map_err(Into::into),
            Command::ScopePage {
                scope,
                result,
                projection,
                query,
            } => {
                self.scope_page_in(tx, *scope, *result, *projection, query)
                    .await
            }
            Command::TaskRead { id, target, family } => {
                self.task_read_in(tx, *id, Some(target), *family).await
            }
        }
    }
}
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
pub enum Command {
    Group {
        id: Uuid,
        change: Operation<GroupChange>,
    },
    GroupRead {
        id: Uuid,
    },
    GroupPreview {
        id: Uuid,
        operation: Uuid,
        expected_revision: u64,
    },
    Scope {
        id: Uuid,
        change: Operation<ScopeChange>,
    },
    ScopeRead {
        id: Uuid,
    },
    GroupPage {
        group: Uuid,
        result: Uuid,
        projection: pages::GroupPageKind,
        query: pages::PageQuery,
    },
    ScopePage {
        scope: Uuid,
        result: Uuid,
        projection: pages::ScopePageKind,
        query: pages::PageQuery,
    },
    TaskRead {
        id: Uuid,
        target: String,
        family: crate::automation::TaskKind,
    },
}

fn group_checked<T>(r: std::result::Result<T, rss_mdm_group_postgres::Rejection>) -> Result<T> {
    r.map_err(|e| match e {
        rss_mdm_group_postgres::Rejection::NotFound
        | rss_mdm_group_postgres::Rejection::Deleted => Error::Planning(
            crate::planning::error::PlanningError::Missing(crate::planning::error::Missing::Group),
        )
        .into(),
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

use rss_mdm_audit_integration::RequestAudit;
mod receipts;

pub mod action_contract;

pub mod error;

impl Planning {
    pub fn compliance(&self) -> rss_mdm_inventory_service::compliance::Compliance {
        rss_mdm_inventory_service::compliance::Compliance::new(
            rss_mdm_inventory_service::compliance::Dependencies {
                audit_store: self.audit_store.clone(),
                runtime: self.runtime.clone(),
                tenant: self.tenant,
                clock: Arc::new(crate::clock::InventoryClock(self.clock.clone())),
                groups: self.groups.clone(),
                tasks: Arc::new(crate::automation::inventory_tasks::InventoryTasks),
                cursor_key: self.cursor_key.clone(),
            },
        )
    }
}

impl Planning {
    fn inventory_groups(&self) -> rss_mdm_inventory_service::groups::Groups {
        rss_mdm_inventory_service::groups::Groups {
            tenant: self.tenant,
            groups: self.groups.clone(),
            cursor_key: self.cursor_key.clone(),
            audit_store: self.audit_store.clone(),
            runtime: self.runtime.clone(),
            clock: Arc::new(crate::clock::InventoryClock(self.clock.clone())),
        }
    }
}
impl rss_mdm_inventory_service::groups::Flow for Planning {
    fn task<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        target: &'a str,
    ) -> rss_mdm_inventory_service::tasks::Pending<'a, Value> {
        Box::pin(async move {
            self.task_read_in(tx, id, Some(target), crate::automation::TaskKind::Group)
                .await
                .map_err(crate::automation::inventory_tasks::failure)
        })
    }
    fn start<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        start: rss_mdm_inventory_service::groups::GroupStart,
    ) -> rss_mdm_inventory_service::tasks::Pending<'a, Value> {
        Box::pin(async move {
            self.start_group_job_in(tx, start)
                .await
                .map_err(crate::automation::inventory_tasks::failure)
        })
    }
    fn assert_unused<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
    ) -> rss_mdm_inventory_service::tasks::Pending<'a, ()> {
        Box::pin(async move {
            self.reject_group_reference(tx, id)
                .await
                .map_err(crate::automation::inventory_tasks::failure)
        })
    }
    fn changed<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        revision: u64,
    ) -> rss_mdm_inventory_service::tasks::Pending<'a, ()> {
        Box::pin(async move {
            self.register_group_inputs_in(tx, id, revision)
                .await
                .map_err(crate::automation::inventory_tasks::failure)
        })
    }
}
