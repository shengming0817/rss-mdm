//! Product planning composition. Core decisions and component storage retain their owners.
use crate::assets;
pub(crate) mod automation;

pub(crate) mod configuration;
mod groups;
pub(crate) mod http;
pub(crate) mod model;
mod pages;
pub(crate) mod policies;
pub(crate) mod references;
pub(crate) mod remote_operations;

mod scopes;
pub(crate) mod sources;
pub(crate) mod storage;

mod wire;
use crate::{Error, Failure};

pub(crate) use http::routes_v2;
pub use model::Permission;
use model::*;
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(crate) struct Planning {
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) automation_task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    pub(crate) runtime: Arc<PgRuntime>,
    cursor_key: ring::hmac::Key,
    pub(crate) asset_reader: assets::planning::SnapshotReader,
    pub(crate) tenant: TenantId,
    pub(crate) clock: Arc<dyn crate::clock::Clock>,
    pub(crate) groups: rss_mdm_group_postgres::GroupStore,
    sources: sources::SourceHeads,
    pub(crate) policy_store: rss_mdm_policy_postgres::PolicyStore,
    pub(crate) catalog: Arc<crate::resource_catalog::ResourceCatalog>,
}
use crate::http_operation::Operation;
use crate::transaction::*;
impl Planning {
    pub(crate) async fn new(
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
            automation_task: std::sync::OnceLock::new(),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
            asset_reader: assets::planning::SnapshotReader { tenant },
            runtime,
            tenant,
            clock,
            groups,
            sources: sources::SourceHeads::new(tenant),
            policy_store,
            catalog,
        })
    }
    // Business rejection must roll back already executed companion steps. Keep its
    // closed category separately; PgError deliberately redacts provider error sources.
    async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> std::result::Result<Value, Error> {
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
            && let Some(old) = crate::planning::receipts::replay(tx, id, &fingerprint).await?
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
            crate::planning::receipts::receipt(tx, id, &fingerprint, &value).await?;
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
            Command::Group { id, change } => self.group_change(tx, *id, change, at).await,
            Command::GroupRead { id } => self.group_read(tx, *id).await,
            Command::GroupPreview {
                id,
                operation,
                expected_revision,
            } => {
                self.group_preview(tx, *id, *operation, *expected_revision, at)
                    .await
            }
            Command::Scope { id, change } => self.scope_change(tx, *id, change, at).await,
            Command::ScopeRead { id } => self.scope_read(tx, *id).await,
            Command::GroupPage {
                group,
                result,
                projection,
                query,
            } => {
                self.group_page_in(tx, *group, *result, *projection, query)
                    .await
            }
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
enum Command {
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

pub(crate) mod action_contract;

pub mod error;

#[cfg(test)]
#[path = "../../tests/planning/mod.rs"]
pub(crate) mod t2;

#[cfg(test)]
#[path = "../../tests/planning/support.rs"]
pub(crate) mod test_support;
