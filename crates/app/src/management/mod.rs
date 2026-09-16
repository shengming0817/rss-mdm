//! Product management composition. Core decisions and component storage retain their owners.
mod config;
mod groups;
mod http;
mod model;
mod plans;
mod publications;
mod resources;
mod scopes;
mod storage;
use crate::{Error, Failure, audit::Audit};
pub(crate) use config::{Config, Resource};
pub(crate) use http::routes;
pub use model::Permission;
use model::*;
use rss_contract::Timepoint;
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(crate) struct Management {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
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
fn checked<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Conflict.into())
}
fn json(v: &impl serde::Serialize) -> Result<Value> {
    input(serde_json::to_value(v))
}
fn now() -> Result<Timepoint> {
    use rss_identity_client::Clock;
    let n = rss_identity_client::SystemClock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    input(Timepoint::try_from(n))
}
fn deadline() -> OperationDeadline {
    let timer = crate::lifecycle::RuntimeTimer;
    OperationDeadline::from_cutoff(
        Deadline::from_timeout(&timer, Duration::from_secs(6)).expect("constant budget"),
        &timer,
    )
}
impl Management {
    async fn new(runtime: Arc<PgRuntime>, tenant: TenantId) -> std::result::Result<Self, Error> {
        storage::admit(&runtime, tenant).await?;
        let groups = rss_mdm_group_postgres::GroupStore::new(runtime.clone(), tenant, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::Runtime))?;
        let policies =
            rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::Runtime))?;
        let resources =
            rss_mdm_resource_postgres::ResourceStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::Runtime))?;
        Ok(Self {
            runtime,
            tenant,
            groups,
            policies,
            resources,
            publications: Default::default(),
            publication_runtime: None,
        })
    }
    // Business rejection must roll back already executed companion steps. Keep its
    // closed category separately; PgError deliberately redacts provider error sources.
    async fn execute(&self, command: &Command, audit: &Audit) -> std::result::Result<Value, Error> {
        let failure = std::sync::Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                deadline(),
                (self, command, audit, &failure),
                |(s, command, audit, failure), tx| {
                    Box::pin(async move {
                        match s.execute_in(tx, command, audit).await {
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
                                    Fault::Storage(e) => (Error::Unavailable(Failure::Runtime), e),
                                    Fault::Sql(e) => {
                                        (Error::Unavailable(Failure::Runtime), e.into())
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
    ) -> Result<Value> {
        storage::lock(tx).await?;
        let (operation, fingerprint) = storage::identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) = storage::replay(tx, id, &fingerprint).await?
        {
            storage::audit(tx, audit).await?;
            return Ok(old);
        }
        let value = self.dispatch(tx, command, now()?).await?;
        if let Some(id) = operation {
            storage::receipt(tx, id, &fingerprint, &value).await?;
        }
        storage::audit(tx, audit).await?;
        Ok(value)
    }
    async fn dispatch(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        at: Timepoint,
    ) -> Result<Value> {
        match command {
            Command::PublicationIntent { .. } => Ok(serde_json::json!({"as_of":at.unix_seconds()})),
            Command::Resource { id, change } => self.resource_change(tx, id, change, at).await,
            Command::ResourceRead { id } => self.resource_read(tx, id).await,
            Command::Group { id, change } => self.group_change(tx, *id, change, at).await,
            Command::GroupRead { id } => self.group_read(tx, *id).await,
            Command::GroupPreview {
                id,
                expected_revision,
            } => self.group_preview(tx, *id, *expected_revision, at).await,
            Command::Scope { id, change } => self.scope_change(tx, *id, change).await,
            Command::ScopeRead { id } => self.scope_read(tx, *id).await,
            Command::Policy { id, change } => self.policy_change(tx, id, change, at).await,
            Command::PolicyRead { id } => self.policy_read(tx, id).await,
            Command::Preview { id, request } => {
                self.preview(tx, id, request.operation_id, &request.input, at)
                    .await
            }
            Command::Save { id, request } => self.save_plan(tx, id, request, at).await,
            Command::PlanRead { id } => {
                json(&storage::preview(tx, *id).await?.ok_or(Error::NotFound)?)
            }
        }
    }
}
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
enum Command {
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
}

#[cfg(test)]
mod tests;
