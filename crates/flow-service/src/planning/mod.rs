//! Product planning composition. Core decisions and component storage retain their owners.
use crate::assets;
use rss_mdm_scope_service::ScopeChange;
pub mod automation;

pub mod execution_source;
pub mod targets;

pub mod directory;
pub mod events;
pub mod model;
pub mod pages;
pub mod policies;
pub mod references;

mod scopes;
pub mod sources;
pub mod storage;

pub mod wire;
use crate::{Error, Failure};

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
    pub(crate) automation_task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    pub runtime: Arc<PgRuntime>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    cursor_key: ring::hmac::Key,
    pub asset_reader: assets::planning::SnapshotReader,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub tenant: TenantId,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub groups: Arc<rss_mdm_group_postgres::GroupStore>,
    sources: sources::SourceHeads,
    scope_binding: rss_mdm_scope_postgres::ScopeBinding,
}
use crate::operation::Operation;
use crate::transaction::*;
impl Planning {
    pub async fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        cursor_key: &[u8],
        objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    ) -> std::result::Result<Self, Error> {
        let groups = rss_mdm_group_postgres::GroupStore::new(runtime.clone(), tenant, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::PlanningAdmission))?;
        let reconcile_messaging =
            rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::PlanningAdmission))?;
        Ok(Self {
            audit_store: audit_store.clone(),
            automation_observation: std::sync::Mutex::new(Default::default()),
            automation_task: std::sync::OnceLock::new(),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
            asset_reader: assets::planning::SnapshotReader { tenant },
            objects,
            reconcile_messaging,
            scope_binding: rss_mdm_scope_postgres::ScopeBinding::new(runtime.clone(), tenant),
            runtime,
            tenant,
            clock,
            groups: Arc::new(groups),
            sources: sources::SourceHeads::new(tenant),
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
        self.execute_with_initialization(command, audit, authorize, None)
            .await
    }
    pub async fn execute_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &crate::authorization::context::AuthorizedPrincipal,
    ) -> std::result::Result<Value, Error> {
        self.execute_with_initialization(
            command,
            audit,
            &|| {
                proof
                    .manage(crate::authorization::Permission::ScopeWrite)
                    .map_err(Error::from)
            },
            Some(proof),
        )
        .await
    }
    async fn execute_with_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
        initialization: Option<&crate::authorization::context::AuthorizedPrincipal>,
    ) -> std::result::Result<Value, Error> {
        match command {
            Command::Scope { id, .. } | Command::ScopeRead { id } => audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Scope,
                &id.to_string(),
            ),
            Command::ScopePage { scope, .. } => audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Scope,
                &scope.to_string(),
            ),
            Command::TaskRead {
                target,
                family: crate::automation::TaskKind::Scope,
                ..
            } => audit.resource_target(rss_mdm_audit_integration::TargetKind::Scope, target),
            Command::TaskRead { .. } => {}
        }
        authorize()?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            &(self, command, audit, authorize, initialization),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, authorize, initialization) = *ctx;
                    if let Some(proof) = initialization {
                        let Command::Scope { id, .. } = command else {
                            return Err(Error::Forbidden.into());
                        };
                        crate::authorization::baseline::check_in(
                            tx,
                            proof,
                            crate::authorization::Permission::ScopeWrite,
                            &id.to_string(),
                        )
                        .await?;
                    }
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
        admit_in(tx).await?;
        if matches!(command, Command::Scope { .. }) {
            crate::transaction::lock(tx).await?;
        }
        authorize()?;
        self.audit_store.prepare_in(tx, audit, &[]).await?;
        let (operation, fingerprint) = storage::identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) =
                rss_mdm_audit_integration::operation_receipts::replay(tx, audit, id, &fingerprint)
                    .await?
        {
            wire::Response::decode(old.clone())?;
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            crate::planning::receipts::audit(tx, &self.audit_store, audit, operation, true).await?;
            authorize()?;
            return Ok(old);
        }
        let at = self
            .clock
            .unix_seconds()
            .map_err(|_| Error::Unavailable(Failure::Clock))?;
        let value = self
            .dispatch(tx, command, checked_input(Timepoint::try_from(at))?, audit)
            .await?;
        // Reject a projection/schema defect before any mutation can commit.
        wire::Response::decode(value.clone())?;
        if let Some(id) = operation {
            rss_mdm_audit_integration::operation_receipts::receipt(
                tx,
                audit,
                id,
                &fingerprint,
                &value,
            )
            .await?;
        }
        crate::planning::receipts::audit(tx, &self.audit_store, audit, operation, false).await?;
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
        audit: &RequestAudit,
    ) -> Result<Value> {
        match command {
            Command::Scope { id, change } => self.scope_change(tx, *id, change, at).await,
            Command::ScopeRead { id } => self.scope_read(tx, *id).await,
            Command::ScopePage {
                scope,
                result,
                projection,
                query,
            } => {
                self.scope_page_in(
                    tx,
                    *scope,
                    *result,
                    *projection,
                    query,
                    &checked_input(rss_mdm_query::cursor::fingerprint(&(
                        audit.snapshot().actor,
                        audit.snapshot().instance,
                    )))?,
                )
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
    Scope {
        id: Uuid,
        change: Operation<ScopeChange>,
    },
    ScopeRead {
        id: Uuid,
    },
    ScopePage {
        scope: Uuid,
        result: Uuid,
        projection: pages::ScopePageKind,
        query: pages::ResultQuery,
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

pub mod error;

mod group_definition;
mod group_references;
impl rss_mdm_inventory_service::groups::Flow for Planning {
    fn define<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        edit: rss_mdm_inventory_service::groups::DefinitionEdit,
    ) -> rss_mdm_inventory_service::tasks::Pending<'a, Value> {
        Box::pin(async move {
            crate::automation::jobs::enqueue_job_in(
                tx,
                edit.change.operation_id,
                &crate::automation::JobInput::GroupDefinition {
                    edit: Box::new(edit),
                },
            )
            .await
            .map_err(crate::automation::inventory_tasks::failure)
        })
    }
    fn graph_changed<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
    ) -> rss_mdm_inventory_service::tasks::Pending<'a, ()> {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("INSERT INTO mdm_planning.source_heads(tenant_id,id,revision) VALUES($1::uuid,'group-graph',1) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=mdm_planning.source_heads.revision+1")
                    .bind(tenant).execute(c).await?; Ok(())
            })).await.map_err(|_| rss_mdm_inventory_service::Error::Unavailable(rss_mdm_inventory_service::Failure::FlowStorage))
        })
    }

    fn current<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
    ) -> rss_mdm_inventory_service::tasks::Pending<'a, bool> {
        Box::pin(async move {
            let source = self
                .capture_group_source_in(tx, id)
                .await
                .map_err(crate::automation::inventory_tasks::failure)?;
            self.source_current_in(tx, &source)
                .await
                .map_err(crate::automation::inventory_tasks::failure)
        })
    }

    fn references<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        request: rss_mdm_inventory_service::groups::references::PageRequest,
    ) -> rss_mdm_inventory_service::tasks::Pending<
        'a,
        rss_mdm_inventory_service::groups::references::Page,
    > {
        Box::pin(async move {
            self.group_references_in(tx, id, request)
                .await
                .map_err(crate::automation::inventory_tasks::failure)
        })
    }

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

impl Planning {
    pub fn automation_state(&self) -> Option<rss_runtime::TaskState> {
        self.automation_task
            .get()
            .map(rss_runtime::TaskStatus::current)
    }
}

pub const ADMISSION_SQL: &str = include_str!("admission.sql");

pub(crate) async fn admit_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    crate::storage::verify_contract(tx, ADMISSION_SQL, Failure::PlanningAdmission).await?;
    crate::storage::verify_contract(
        tx,
        crate::automation::ADMISSION_SQL,
        Failure::AutomationAdmission,
    )
    .await
}
