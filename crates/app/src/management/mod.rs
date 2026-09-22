//! Product management composition. Core decisions and component storage retain their owners.
pub(crate) mod assets;
pub(crate) mod automation;
mod config;
mod groups;
mod http;
mod model;
mod pages;
mod plans;
mod publications;
mod resources;
mod scopes;
mod storage;
mod wire;
use crate::{Error, Failure, audit::Audit};
pub(crate) use config::Config;
pub(crate) use http::{routes, routes_v2};
use model::*;
pub use model::{Missing, Permission};
use rss_contract::Timepoint;
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(crate) struct Management {
    pub(crate) automation_task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    runtime: Arc<PgRuntime>,
    asset_cursor_key: ring::hmac::Key,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    groups: rss_mdm_group_postgres::GroupStore,
    policies: rss_mdm_policy_postgres::PolicyStore,
    resources: rss_mdm_resource_postgres::ResourceStore,
    publications:
        std::collections::BTreeMap<String, crate::software_publication::PublicationService>,
    publication_runtime: Option<Arc<PgRuntime>>,
}
#[derive(Debug, thiserror::Error)]
enum Fault {
    #[error(transparent)]
    Request(#[from] Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
type Result<T> = std::result::Result<T, Fault>;
fn input<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Malformed.into())
}
fn stored<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Unavailable(Failure::ManagementStorage).into())
}
fn checked<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Conflict.into())
}
fn json(v: &impl serde::Serialize) -> Result<Value> {
    input(serde_json::to_value(v))
}
fn deadline() -> OperationDeadline {
    let timer = crate::lifecycle::RuntimeTimer;
    OperationDeadline::from_cutoff(
        Deadline::from_timeout(&timer, Duration::from_secs(6)).expect("constant budget"),
        &timer,
    )
}
impl Management {
    async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
    ) -> std::result::Result<Self, Error> {
        storage::admit(&runtime, tenant).await?;
        let groups = rss_mdm_group_postgres::GroupStore::new(runtime.clone(), tenant, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::ManagementAdmission))?;
        let policies =
            rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::ManagementAdmission))?;
        let resources =
            rss_mdm_resource_postgres::ResourceStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::ManagementAdmission))?;
        let key = storage::cursor_key(&runtime, tenant).await?;
        Ok(Self {
            automation_task: std::sync::OnceLock::new(),
            asset_cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
            runtime,
            tenant,
            clock,
            groups,
            policies,
            resources,
            publications: Default::default(),
            publication_runtime: None,
        })
    }
    // Business rejection must roll back already executed companion steps. Keep its
    // closed category separately; PgError deliberately redacts provider error sources.
    async fn execute(
        &self,
        command: &Command,
        audit: &Audit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> std::result::Result<Value, Error> {
        authorize()?;
        let failure = std::sync::Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                deadline(),
                (self, command, audit, &failure, authorize),
                |(s, command, audit, failure, authorize), tx| {
                    Box::pin(async move {
                        let partitions = match command {
                            Command::Group { id, .. } => vec![s.groups.partition(&id.to_string())?],
                            Command::Resource { id, .. } => vec![s.resources.partition(id)?],
                            Command::Policy { id, .. } | Command::Save { id, .. } => {
                                vec![s.policies.partition(id)?]
                            }
                            _ => Vec::new(),
                        };
                        tx.prepare_outbox_partitions(&partitions).await?;
                        match s.execute_in(tx, command, audit, authorize).await {
                            Ok(v) => {
                                audit.mark_commit_started();
                                Ok(v)
                            }
                            Err(e) => {
                                let (reason, db) = match e {
                                    Fault::Request(e) => (
                                        e,
                                        sqlx::Error::Protocol("management rejected".into()).into(),
                                    ),
                                    Fault::Storage(e) => {
                                        (Error::Unavailable(Failure::ManagementStorage), e)
                                    }
                                    Fault::Sql(e) => {
                                        let reason = if e
                                            .as_database_error()
                                            .and_then(|d| d.code())
                                            .is_some_and(|c| c == "40001" || c == "40P01")
                                        {
                                            Error::Conflict
                                        } else {
                                            Error::Unavailable(Failure::Runtime)
                                        };
                                        (reason, e.into())
                                    }
                                };
                                *failure.lock().expect("request failure lock") = Some(reason);
                                Err(db)
                            }
                        }
                    })
                },
            )
            .await;
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |_| Err(Error::Unavailable(Failure::Runtime)),
            |_| {
                Err(failure
                    .into_inner()
                    .expect("request failure lock")
                    .unwrap_or(Error::Unavailable(Failure::Runtime)))
            },
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Runtime)),
        )
    }
    async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        audit: &Audit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> Result<Value> {
        storage::lock(tx).await?;
        authorize()?;
        let (operation, fingerprint) = storage::identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) = storage::replay(tx, id, &fingerprint).await?
        {
            if !matches!(command, Command::PublicationIntent { .. }) {
                wire::Response::decode(old.clone())?;
            }
            audit.management_result(crate::audit::ManagementResult::Replayed);
            storage::audit(tx, audit).await?;
            authorize()?;
            return Ok(old);
        }
        let at = self
            .clock
            .unix_seconds()
            .map_err(|_| Error::Unavailable(Failure::Clock))?;
        let value = self
            .dispatch(tx, command, input(Timepoint::try_from(at))?)
            .await?;
        // Reject a projection/schema defect before any mutation can commit.
        if !matches!(command, Command::PublicationIntent { .. }) {
            wire::Response::decode(value.clone())?;
        }
        if let Some(id) = operation {
            storage::receipt(tx, id, &fingerprint, &value).await?;
        }
        storage::audit(tx, audit).await?;
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
            Command::Asset { command } => self.asset_dispatch(tx, command, at).await,
            Command::PublicationIntent { .. } => Ok(serde_json::json!({"as_of":at.unix_seconds()})),
            Command::Resource { id, change } => self.resource_change(tx, id, change, at).await,
            Command::ResourceRead { id } => self.resource_read(tx, id).await,
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
            Command::Policy { id, change } => self.policy_change(tx, id, change, at).await,
            Command::PolicyRead { id } => self.policy_read(tx, id).await,
            Command::Preview { id, request } => {
                self.preview(tx, id, request.operation_id, &request.input, at)
                    .await
            }
            Command::Save { id, request } => self.save_plan(tx, id, request, at).await,
            Command::PlanRead { id } => {
                self.task_read_in(tx, *id, None, automation::TaskKind::Policy)
                    .await
            }
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
            Command::PolicyPage {
                policy,
                result,
                projection,
                query,
            } => {
                self.policy_page_in(tx, policy, *result, *projection, query)
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
    Asset {
        command: assets::Command,
    },
    PublicationIntent {
        source: String,
        id: String,
        request: Operation<publications::Change>,
    },
    Resource {
        id: String,
        change: Operation<resources::Change>,
    },
    ResourceRead {
        id: String,
    },
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
    Policy {
        id: String,
        change: Operation<PolicyChange>,
    },
    PolicyRead {
        id: String,
    },
    Preview {
        id: String,
        request: Operation<PreviewInput>,
    },
    Save {
        id: String,
        request: Operation<SavePlan>,
    },
    PlanRead {
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
    PolicyPage {
        policy: String,
        result: Uuid,
        projection: pages::PolicyPageKind,
        query: pages::PageQuery,
    },
    TaskRead {
        id: Uuid,
        target: String,
        family: automation::TaskKind,
    },
}

#[cfg(test)]
mod tests;

fn group_checked<T>(r: std::result::Result<T, rss_mdm_group_postgres::Rejection>) -> Result<T> {
    r.map_err(|e| match e {
        rss_mdm_group_postgres::Rejection::NotFound
        | rss_mdm_group_postgres::Rejection::Deleted => {
            Error::ManagementNotFound(Missing::Group).into()
        }
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
