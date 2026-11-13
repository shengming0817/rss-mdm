//! Group application tasks. RSS alone owns execution claims and retry policy.
use super::*;
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskInput {
    Definition {
        edit: Box<DefinitionEdit>,
    },
    Calculation {
        authority: Vec<RequiredAuthority>,
        group: Uuid,
        base_revision: i64,
        asset_cut: rss_mdm_inventory::AssetCut,
        automatic: bool,
        covered_inputs: i64,
    },
}

impl TaskInput {
    pub fn target(&self) -> Uuid {
        match self {
            Self::Definition { edit } => edit.group,
            Self::Calculation { group, .. } => *group,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Definition { .. } => "group_definition",
            Self::Calculation { .. } => "group",
        }
    }
}

pub struct TaskState {
    pub input: TaskInput,
    pub completed: bool,
    pub failure: Option<String>,
    pub cursor: Option<Uuid>,
    pub definition_progress: Option<super::definition::Cursor>,
}

impl Groups {
    pub(crate) fn check_task_transaction(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }

    pub(crate) async fn read_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<TaskState> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT input,kind,target,completed,failure,cursor,definition_progress FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        let input: TaskInput = stored(serde_json::from_value(row.try_get("input")?))?;
        if input.target().is_nil()
            || input.target() != row.try_get::<Uuid, _>("target")?
            || input.kind() != row.try_get::<String, _>("kind")?
        {
            return Err(Error::Unavailable(Failure::GroupStorage).into());
        }
        Ok(TaskState {
            input,
            completed: row.try_get("completed")?,
            failure: row.try_get("failure")?,
            cursor: row.try_get("cursor")?,
            definition_progress: row
                .try_get::<Option<serde_json::Value>, _>("definition_progress")?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Unavailable(Failure::GroupStorage))?,
        })
    }

    pub(crate) async fn enqueue_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        input: &TaskInput,
    ) -> Result<crate::tasks::JobAccepted> {
        self.check_task_transaction(tx)?;
        if id.is_nil() || input.target().is_nil() {
            return Err(Error::Malformed.into());
        }
        let document = checked_input(serde_json::to_string(input))?;
        if document.len() > 1_048_576 {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let kind = input.kind();
        let target = input.target();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_assets.group_tasks(tenant_id,id,kind,target,input) VALUES($1::uuid,$2,$3,$4,$5::jsonb)")
                .bind(tenant).bind(id).bind(kind).bind(target).bind(document).execute(c).await?;
            Ok(())
        })).await?;
        let target = self::target(self.tenant, id);
        self.reconcile_messaging.wake_in(tx, &target, &rss_reconcile::ResourceSet::empty(target.scope().tenant()), (), |_, tx| Box::pin(async move {
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'groups')").execute(c).await?;
                Ok(())
            })).await
        })).await?;
        Ok(accepted(id, input))
    }

    pub(crate) async fn replace_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        old: Uuid,
        new: Uuid,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_assets.group_tasks SET replacement_task=$3 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(old).bind(new).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
}

pub(crate) fn accepted(id: Uuid, input: &TaskInput) -> crate::tasks::JobAccepted {
    crate::tasks::JobAccepted {
        task: id,
        kind: input.kind().into(),
        target: input.target().to_string(),
        status_url: format!("/api/v1/groups/{}/tasks/{id}", input.target()),
    }
}

pub fn target(tenant: TenantId, id: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.groups").expect("constant scope"),
        format!("task:{id}"),
    )
    .expect("UUID target")
}

impl Groups {
    pub(crate) async fn finish_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        failure: Option<&str>,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let failure_owned = failure.map(str::to_owned);
        let changed = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar::<_, Uuid>("UPDATE mdm_assets.group_tasks SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed RETURNING target")
                .bind(tenant).bind(id).bind(failure_owned).fetch_optional(c).await
        })).await?;
        let state = self.read_task_in(tx, id).await?;
        if !state.completed {
            return Err(Error::Conflict.into());
        }
        self.clear_evaluation(tx, id).await?;
        group_checked(self.groups.clear_definition_walk_in(tx, id).await?)?;
        if let Some(target) = changed {
            let action = match failure {
                None => "automation_completed",
                Some("superseded") => "automation_superseded",
                Some(_) => "automation_failed",
            };
            let audit = rss_mdm_audit_integration::RequestAudit::new(
                rss_mdm_audit_integration::Origin::Background,
                rss_mdm_audit_integration::StorageProfile::Mdm,
                self.tenant.to_string(),
                action,
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            audit.identify_service("service:group-automation");
            audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Group,
                &target.to_string(),
            );
            audit.owned_operation(
                rss_mdm_audit_integration::operation::OperationOwner::GroupTask,
                id,
                action,
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let fact = rss_mdm_audit_integration::Fact::business(
                &audit,
                rss_mdm_audit_integration::operation::OperationOwner::GroupTask,
                &format!("group-task:{id}:terminal"),
                200,
                if failure.is_some() {
                    "failed"
                } else {
                    "success"
                },
                None,
            )
            .map_err(Error::from)?;
            let result = self
                .audit_store
                .append_in(tx, &fact)
                .await
                .map_err(Error::from);
            audit.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            result?;
        }
        Ok(())
    }
}

impl Groups {
    pub(crate) async fn task_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        target: &str,
    ) -> Result<Value> {
        let state = self.read_task_in(tx, id).await?;
        if state.input.target().to_string() != target {
            return Err(Error::Group(GroupMissing::Group).into());
        }
        let (processed, members) =
            if state.failure.is_none() && matches!(state.input, TaskInput::Calculation { .. }) {
                let build = group_checked(
                    self.groups
                        .build_in(
                            tx,
                            checked_input(rss_mdm_group::OperationId::parse(&id.to_string()))?,
                        )
                        .await?,
                )?;
                (build.processed as u64, build.members as u64)
            } else {
                (0, 0)
            };
        let tenant = self.tenant.to_string();
        let replacement_task = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT replacement_task FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        let status = if state.failure.as_deref() == Some("superseded") {
            "superseded"
        } else if state.failure.is_some() {
            "failed"
        } else if state.completed {
            "completed"
        } else if processed > 0 || (state.cursor.is_some() || state.definition_progress.is_some()) {
            "running"
        } else {
            "pending"
        };
        Ok(
            serde_json::json!({"task":id,"kind":state.input.kind(),"target":target,"status":status,"processed":processed,"members":members,"failure":state.failure,"failure_detail":Option::<Value>::None,"replacement_task":replacement_task}),
        )
    }
}

impl TaskInput {
    pub(crate) fn authority(&self) -> &[RequiredAuthority] {
        match self {
            Self::Definition { edit } => &edit.authority,
            Self::Calculation { authority, .. } => authority,
        }
    }
}
impl Groups {
    pub(crate) async fn authorize_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        input: &TaskInput,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        if matches!(input, TaskInput::Calculation { .. })
            && group_checked(
                self.groups
                    .build_in(
                        tx,
                        checked_input(rss_mdm_group::OperationId::parse(&id.to_string()))?,
                    )
                    .await?,
            )?
            .receipt
            .is_some()
        {
            return Ok(());
        }
        if matches!(input, TaskInput::Definition { .. }) && input.authority().is_empty() {
            return Err(Error::Forbidden.into());
        }
        for required in input.authority() {
            if required.evidence.actor().tenant_id() != self.tenant.to_string() {
                return Err(Error::Forbidden.into());
            }
            let required = required.clone();
            let valid = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        let now: i64 = sqlx::query_scalar(
                            "SELECT extract(epoch FROM clock_timestamp())::bigint",
                        )
                        .fetch_one(&mut *c)
                        .await?;
                        Ok(required
                            .evidence
                            .valid(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                required.permission,
                                now,
                            )
                            .await)
                    })
                })
                .await??;
            if !valid {
                return Err(Error::Forbidden.into());
            }
        }
        Ok(())
    }
}

use std::{future::Future, pin::Pin};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = std::result::Result<T, Error>> + Send + 'a>>;
/// Group-owned accepted task result.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobAccepted {
    pub task: Uuid,
    pub kind: String,
    pub target: String,
    pub status_url: String,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
pub struct TaskRead {
    pub task: Uuid,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub processed: u64,
    pub members: u64,
    pub failure: Option<String>,
    pub failure_detail: Option<TaskDiagnostic>,
    pub replacement_task: Option<Uuid>,
}

/// Durable task diagnostic emitted by the existing scheduling owner.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskDiagnostic {
    GroupInputPending,
}

impl Groups {
    pub async fn task_receipt(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p), |(s, p), tx| {
            Box::pin(async move {
                let grant = crate::transaction::query_authority(tx, p).await?;
                grant.require(
                    p,
                    rss_mdm_authorization_service::Permission::GroupRead,
                    None,
                )?;
                grant.require_all_devices(
                    p,
                    rss_mdm_authorization_service::Permission::InventoryRead,
                )?;
                let state = s.read_task_in(tx, id).await?;
                let mut value = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                value.object = Some(state.input.target().to_string());
                value.accepted = Some(true);
                value.executions.push(id);
                let detail = s
                    .task_read_in(tx, id, &state.input.target().to_string())
                    .await?;
                value.state = Some(detail["status"].as_str().ok_or(Error::Conflict)?.into());
                p.check_live()?;
                Ok(Some(value))
            })
        })
        .await
    }
}
