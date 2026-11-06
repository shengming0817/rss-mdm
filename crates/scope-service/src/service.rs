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
    pub(crate) read_pool: sqlx::PgPool,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) store: rss_mdm_scope_postgres::ScopeBinding,
    pub(crate) clock: Arc<dyn clock::Clock>,
    pub(crate) cursor_key: ring::hmac::Key,
    pub(crate) objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub(crate) groups: Arc<rss_mdm_group_postgres::GroupSources>,
    pub(crate) projection: crate::projection::ScopeProjection,
    pub(crate) dependents: Arc<dyn sources::ScopeDependents>,
    pub(crate) input_state: std::sync::atomic::AtomicU8,
    pub(crate) runner_health: std::sync::Mutex<crate::health::RunnerObservation>,
    pub(crate) task: std::sync::OnceLock<rss_runtime::TaskStatus>,
}
pub struct Dependencies {
    pub read_pool: sqlx::PgPool,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub groups: Arc<rss_mdm_group_postgres::GroupSources>,
    pub dependents: Arc<dyn sources::ScopeDependents>,
    pub cursor_key: Vec<u8>,
}
impl Scopes {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.store.profile()
    }
    pub async fn new(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn clock::Clock>,
        dependencies: Dependencies,
    ) -> std::result::Result<Self, Error> {
        let store = rss_mdm_scope_postgres::ScopeBinding::new(profile, runtime.clone(), tenant);
        let s = Self {
            projection: crate::projection::ScopeProjection::new(profile, runtime.clone(), tenant),
            runtime,
            tenant,
            clock,
            store,
            read_pool: dependencies.read_pool,
            audit_store: dependencies.audit_store,
            reconcile_messaging: dependencies.reconcile_messaging,
            objects: dependencies.objects,
            groups: dependencies.groups,
            dependents: dependencies.dependents,
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &dependencies.cursor_key),
            task: Default::default(),
            input_state: Default::default(),
            runner_health: Default::default(),
        };
        s.runtime
            .local_tx_with_context(tenant, deadline(), &s, |s, tx| {
                Box::pin(async move {
                    s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                    s.store.admit_in(tx).await.map_err(|e| match e {
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
        proof: &crate::authorization::context::AuthorizedPrincipal,
    ) -> std::result::Result<Value, Error> {
        self.execute_with_initialization(command, audit, proof, false)
            .await
    }
    pub async fn execute_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &crate::authorization::context::AuthorizedPrincipal,
    ) -> std::result::Result<Value, Error> {
        self.execute_with_initialization(command, audit, proof, true)
            .await
    }
    async fn execute_with_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &crate::authorization::context::AuthorizedPrincipal,
        initialization: bool,
    ) -> std::result::Result<Value, Error> {
        if audit.profile() != self.profile()
            || proof.tenant_id() != self.tenant.to_string()
            || (!initialization && proof.initialization_authority().is_some())
        {
            return Err(Error::Forbidden);
        }
        proof.bind_audit(audit)?;
        if let Command::Scope { change, .. } = command {
            audit.owned_operation(
                rss_mdm_audit_integration::operation::OperationOwner::Scope,
                change.operation_id,
                "management_write",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
        }
        match command {
            Command::Scope { id, .. } | Command::ScopeRead { id } => audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Scope,
                &id.to_string(),
            ),
            Command::TaskRead { target, .. } => {
                audit.resource_target(rss_mdm_audit_integration::TargetKind::Scope, target)
            }
        }
        let write = matches!(command, Command::Scope { .. });
        audit.set_action(
            if write {
                "management_write"
            } else {
                "management_read"
            },
            if write {
                rss_mdm_audit_integration::AuditIntent::Management
            } else {
                rss_mdm_audit_integration::AuditIntent::Routine
            },
        );
        proof.manage(if write {
            crate::authorization::Permission::ScopeWrite
        } else {
            crate::authorization::Permission::ScopeRead
        })?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, command, audit, proof, initialization),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, proof, initialization) = *ctx;
                    s.audit_store.prepare_in(tx, audit, &[]).await?;
                    if initialization {
                        let Command::Scope { id, change } = command else {
                            return Err(Error::Forbidden.into());
                        };
                        if !matches!(change.input, ScopeChange::Put { .. }) {
                            return Err(Error::Forbidden.into());
                        }
                        crate::authorization::baseline::check_in(
                            tx,
                            proof,
                            crate::authorization::Permission::ScopeWrite,
                            &id.to_string(),
                        )
                        .await?;
                    }
                    s.execute_in(tx, command, audit, proof).await
                })
            },
        )
        .await
    }
    async fn authorize_command_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &crate::authorization::context::AuthorizedPrincipal,
        command: &Command,
    ) -> Result<()> {
        use crate::authorization::Permission;
        let authority = crate::action_admission::current(tx, proof).await?;
        authority.require(
            proof,
            if matches!(command, Command::Scope { .. }) {
                Permission::ScopeWrite
            } else {
                Permission::ScopeRead
            },
            None,
        )?;
        let grouped = match command {
            Command::Scope { change, .. } if matches!(&change.input,ScopeChange::Put{definition} if definition.references().iter().any(|r|matches!(r,rss_mdm_scope::Reference::Group(_)))) => {
                true
            }
            Command::Scope { id, change } if matches!(change.input, ScopeChange::Recompute) => {
                if change.expected_revision == 0 {
                    return Err(Error::Malformed.into());
                }
                let definition = match self
                    .store
                    .definition_at_in(tx, *id, change.expected_revision)
                    .await
                {
                    Ok(definition) => definition,
                    Err(rss_mdm_scope_postgres::BindingError::Missing) => {
                        self.store.head_in(tx, *id, false).await?;
                        return Err(Error::Conflict.into());
                    }
                    Err(error) => return Err(error.into()),
                };
                definition
                    .references()
                    .iter()
                    .any(|r| matches!(r, rss_mdm_scope::Reference::Group(_)))
            }
            _ => false,
        };
        if grouped {
            authority.require(proof, Permission::GroupRead, None)?;
        }
        if matches!(command, Command::TaskRead { .. }) {
            authority.require_all_devices(proof, Permission::InventoryRead)?;
        }
        proof.check_live()?;
        Ok(())
    }
    async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        audit: &RequestAudit,
        proof: &crate::authorization::context::AuthorizedPrincipal,
    ) -> Result<Value> {
        self.store.admit_in(tx).await?;
        self.authorize_command_in(tx, proof, command).await?;

        let (operation, fingerprint) = crate::identity(command, audit)?;
        let actor = audit.snapshot().actor;
        if let Some(id) = operation
            && let Some(old) = self
                .store
                .replay_operation_in(
                    tx,
                    actor.as_deref().ok_or(Error::Malformed)?,
                    id,
                    &fingerprint,
                )
                .await?
        {
            wire::Response::decode(old.clone())?;
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            crate::receipts::audit(tx, &self.audit_store, audit, operation, true).await?;
            self.authorize_command_in(tx, proof, command).await?;
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
            self.store
                .record_operation_in(
                    tx,
                    actor.as_deref().ok_or(Error::Malformed)?,
                    id,
                    &fingerprint,
                    &value,
                )
                .await?;
        }
        crate::receipts::audit(tx, &self.audit_store, audit, operation, false).await?;
        self.authorize_command_in(tx, proof, command).await?;
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
            Command::Scope { id, change } => self.scope_change(tx, *id, change, at).await,
            Command::ScopeRead { id } => self.scope_read(tx, *id).await,
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
    TaskRead {
        id: Uuid,
        target: String,
    },
}
