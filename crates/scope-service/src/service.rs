use crate::operation::Operation;
use crate::transaction::*;
use crate::*;
use rss_contract::Timepoint;
use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub struct Scopes {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) store: rss_mdm_scope_postgres::ScopeBinding,
    pub(crate) clock: Arc<dyn clock::Clock>,
    pub(crate) cursor_key: ring::hmac::Key,
    pub(crate) objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub(crate) groups: Arc<rss_mdm_group_postgres::GroupStore>,
    pub(crate) projection: Arc<dyn sources::ChannelProjectionPublisher>,
    pub(crate) dependents: Arc<dyn sources::ScopeDependents>,
    pub(crate) input_state: std::sync::atomic::AtomicU8,
    pub(crate) runner_health: std::sync::Mutex<crate::health::RunnerObservation>,
    pub(crate) task: std::sync::OnceLock<rss_runtime::TaskStatus>,
}
pub struct Dependencies {
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub groups: Arc<rss_mdm_group_postgres::GroupStore>,
    pub projection: Arc<dyn sources::ChannelProjectionPublisher>,
    pub dependents: Arc<dyn sources::ScopeDependents>,
    pub cursor_key: Vec<u8>,
}
impl Scopes {
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn clock::Clock>,
        dependencies: Dependencies,
    ) -> std::result::Result<Self, Error> {
        let store = rss_mdm_scope_postgres::ScopeBinding::new(runtime.clone(), tenant);
        let s = Self {
            runtime,
            tenant,
            clock,
            store,
            audit_store: dependencies.audit_store,
            reconcile_messaging: dependencies.reconcile_messaging,
            objects: dependencies.objects,
            groups: dependencies.groups,
            projection: dependencies.projection,
            dependents: dependencies.dependents,
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &dependencies.cursor_key),
            task: Default::default(),
            input_state: Default::default(),
            runner_health: Default::default(),
        };
        s.runtime
            .local_tx_with_context(tenant, deadline(), &s.store, |store, tx| {
                Box::pin(async move {
                    store.admit_in(tx).await.map_err(|e| match e {
                        rss_mdm_scope_postgres::BindingError::Storage(e) => e,
                        _ => sqlx::Error::Protocol("Scope admission".into()).into(),
                    })
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::Admission)),
                |_| Err(Error::Unavailable(Failure::Admission)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::Admission)),
            )?;
        Ok(s)
    }
    pub fn task_state(&self) -> Option<rss_runtime::TaskState> {
        self.task.get().map(rss_runtime::TaskStatus::current)
    }
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
            Command::TaskRead { target, .. } => {
                audit.resource_target(rss_mdm_audit_integration::TargetKind::Scope, target)
            }
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
        self.store.admit_in(tx).await?;
        if matches!(command, Command::Scope { .. }) {
            crate::transaction::lock(tx).await?;
        }
        authorize()?;
        self.audit_store.prepare_in(tx, audit, &[]).await?;
        let (operation, fingerprint) = crate::identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) =
                rss_mdm_audit_integration::operation_receipts::replay(tx, audit, id, &fingerprint)
                    .await?
        {
            wire::Response::decode(old.clone())?;
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            crate::receipts::audit(tx, &self.audit_store, audit, operation, true).await?;
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
        crate::receipts::audit(tx, &self.audit_store, audit, operation, false).await?;
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
            Command::TaskRead { id, target } => self.task_read_in(tx, *id, Some(target)).await,
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
    },
}
