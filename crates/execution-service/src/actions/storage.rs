use super::state::RunState;
use crate::Error;
use crate::Target;
use crate::sources::admission::ExecutionPolicy;
use crate::sources::software::SoftwareExecutionPolicy;
use crate::{Result, checked_input, storage, stored};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    DeviceAccess { version: Uuid, delivery: Uuid },
    Policy { version: Uuid },
    RetirementSoftware { version: Uuid, retirement: Uuid },
}
impl Source {
    pub fn columns(self) -> (&'static str, Uuid) {
        match self {
            Self::DeviceAccess { version, .. } => ("device_access", version),
            Self::Policy { version } | Self::RetirementSoftware { version, .. } => {
                ("policy", version)
            }
        }
    }
    pub fn audit(self, audit: &rss_mdm_audit_integration::RequestAudit) {
        let (_, version) = self.columns();
        audit.plan(version);
    }
}
pub struct Run {
    pub id: Uuid,
    pub source: Source,
    pub target: Target,
    pub available_at: i64,
    pub deadline: i64,
    pub state: RunState,
    pub result: Option<Value>,
    pub invocation: Option<crate::self_service::Invocation>,
    pub source_objects: Vec<crate::source_authority::DeviceObject>,
}
pub async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, true).await
}
pub async fn read_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, false).await
}
async fn run_in(tx: &mut PgTransaction<'_>, id: Uuid, locked: bool) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{if locked {sqlx::query("SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(&tenant).bind(id).fetch_optional(&mut *c).await?;}sqlx::query("SELECT (SELECT w.operation FROM mdm_devices.retirement_work w JOIN mdm_devices.retirements o ON(o.tenant_id,o.id)=(w.tenant_id,w.operation) WHERE w.tenant_id=mdm_commands.action_runs.tenant_id AND w.execution=mdm_commands.action_runs.id AND o.version<>mdm_commands.action_runs.policy_version) AS retirement,source_kind,policy_version,device,registration::text,generation,available_at,deadline,state,result,invocation,source_objects FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid ").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::Execution(crate::missing::ExecutionError::MissingTask))?;
    Ok(Run {
        id,
        source: match row.try_get::<&str, _>("source_kind")? {
            "device_access" => Source::DeviceAccess {
                version: row.try_get("policy_version")?,
                delivery: id,
            },
            "policy" => {
                if let Some(retirement) = row.try_get::<Option<Uuid>, _>("retirement")? {
                    Source::RetirementSoftware {
                        version: row.try_get("policy_version")?,
                        retirement,
                    }
                } else {
                    Source::Policy {
                        version: row.try_get("policy_version")?,
                    }
                }
            }
            _ => return Err(Error::Unavailable(crate::Failure::CommandInvariant).into()),
        },
        target: Target {
            device: row.try_get("device")?,
            registration: stored(Uuid::parse_str(&row.try_get::<String, _>("registration")?))?,
            generation: row.try_get("generation")?,
        },
        source_objects: stored(serde_json::from_value(row.try_get("source_objects")?))?,
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        state: stored(serde_json::from_value(row.try_get("state")?))?,
        result: row.try_get("result")?,
        invocation: row
            .try_get::<Option<Value>, _>("invocation")?
            .map(serde_json::from_value)
            .map(crate::stored)
            .transpose()?,
    })
}
pub async fn save_run(tx: &mut PgTransaction<'_>, run: &Run) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id.to_string();
    let state = checked_input(serde_json::to_value(&run.state))?;
    let result = run.result.clone();
    let previous=tx.with_connection({let tenant=tenant.clone();let id=id.clone();move|c|Box::pin(async move {sqlx::query_scalar::<_,Value>("SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).fetch_one(c).await})}).await?;
    let changed = tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4)").bind(tenant).bind(id).bind(state).bind(result).execute(c).await})).await?;
    if changed.rows_affected() > 0 {
        crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    }
    let terminal = match run.state.execution {
        super::state::Execution::Succeeded => Some("succeeded"),
        super::state::Execution::Failed => Some("failed"),
        _ if run.state.cancellation == super::state::Cancellation::Confirmed => Some("cancelled"),
        _ => None,
    };
    // RetirementSoftware is cleanup work, not a policy execution terminal event.
    if let (Some(status), Source::Policy { version }) = (terminal, run.source) {
        let old = previous.get("execution").and_then(Value::as_str);
        let cancelled = previous.get("cancellation").and_then(Value::as_str) == Some("confirmed");
        if old != Some(status) && !(status == "cancelled" && cancelled) {
            use rss_mdm_webhook_service::{events, model::*};
            let event = Event {
                event_id: events::identity(run.id, &format!("terminal:{status}")),
                event_type: EventType::PolicyTerminal,
                version: 1,
                occurred_at: crate::storage::now(tx).await?,
                tenant_id: stored(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                device_id: run.target.device.clone(),
                data: EventData::Policy {
                    run_id: run.id,
                    policy_version: version,
                    registration_id: run.target.registration,
                    generation: run.target.generation,
                    status: status.into(),
                },
            };
            events::emit_in(tx, event)
                .await
                .map_err(rss_transactional_messaging_postgres::PgError::from)?;
        }
    }
    Ok(())
}
pub async fn replay(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    storage::lock(tx, &format!("action-request:{actor}:{id}")).await?;
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT fingerprint,response FROM mdm_commands.action_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_optional(c).await})).await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Err(Error::Conflict.into());
        }
        Ok(row.try_get("response")?)
    })
    .transpose()
}
pub async fn receipt(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: Vec<u8>,
    response: &Value,
    audit_details: Option<Value>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let response = response.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_receipts(tenant_id,actor,id,fingerprint,response,audit_details) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)").bind(tenant).bind(actor).bind(id.to_string()).bind(fingerprint).bind(response).bind(audit_details).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn audit_details(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT audit_details FROM mdm_commands.action_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_one(c).await})).await.map_err(Into::into)
}

pub enum ScheduledPolicy {
    DeviceAccess(crate::device_access::Plan),
    Retirement(crate::unmanage::RetirementPlan),
    Credential(ExecutionPolicy<crate::credential_tasks::FrozenCredential>),
    AgentCollection(ExecutionPolicy<crate::action_contract::FrozenAgentCollection>),
    Script(Box<ExecutionPolicy>),
    Native(ExecutionPolicy<crate::action_contract::FrozenNativeCollection>),
    Software(SoftwareExecutionPolicy),
    Enrollment(crate::sources::enrollment::EnrollmentPolicy),
}
pub struct TaskIssue {
    pub run: Uuid,
    pub attempt: Uuid,
    pub permit: rss_mdm_agent_wire::runtime::TaskPermit,
    pub expiry: i64,
}
impl ScheduledPolicy {
    pub fn owner(&self) -> Uuid {
        match self {
            Self::DeviceAccess(v) => v.owner,
            Self::Credential(v) => v.owner,
            Self::AgentCollection(v) => v.owner,
            Self::Script(v) => v.owner,
            Self::Native(v) => v.owner,
            Self::Software(v) => v.owner,
            Self::Enrollment(v) => v.owner,
            Self::Retirement(v) => v.owner,
        }
    }
    pub async fn authorized_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        if let Self::Retirement(v) = self {
            return v.allowed_in(tx, target, None).await;
        }
        if let Self::Software(v) = self
            && v.assignment.retirement.is_some()
        {
            let Some((platform, architecture)) =
                agent_profile_in(service, tx, target.registration).await?
            else {
                return Ok(false);
            };
            return v
                .assignment
                .authorized_in(
                    &service.admission(),
                    tx,
                    &target.device,
                    platform,
                    architecture,
                    now,
                )
                .await;
        }
        let tenant = tx.tenant_id().to_string();
        let device = target.device.clone();
        let allowed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_registration_service::lifecycle::work_allowed_in(
                        c, &tenant, &device,
                    )
                    .await)
                })
            })
            .await??;
        if !allowed {
            return Ok(false);
        }
        match self {
            Self::DeviceAccess(v) => v.allowed_in(service, tx, target).await,
            Self::Retirement(v) => v.allowed_in(tx, target, None).await,
            Self::Credential(v) => Ok(crate::credential_tasks::eligible(
                service,
                tx,
                target,
                v.frozen.input.architecture,
            )
            .await?
                && v.frozen.authorized_in(service, tx, target, now).await?
                && v.authorized_in(&service.source, tx, &target.device, now)
                    .await?),
            Self::AgentCollection(v) => Ok(crate::agent_collection_eligibility::check_in(
                tx,
                service.agent_store.clone(),
                target,
                v.frozen.input.platform,
                v.frozen.input.architecture,
                &v.frozen.definition,
            )
            .await?
                && v.frozen.authorized_in(tx, target, now).await?
                && v.authorized_in(&service.source, tx, &target.device, now)
                    .await?),
            Self::Script(v) => Ok(crate::script_eligibility::require_in(
                tx,
                service.agent_store.clone(),
                target,
                &v.frozen,
            )
            .await?
                && v.authorized_in(&service.source, tx, &target.device, now)
                    .await?),
            Self::Native(v) => {
                v.authorized_in(&service.source, tx, &target.device, now)
                    .await
            }
            Self::Enrollment(v) => v.authorized_in(service, tx, target, now).await,
            Self::Software(v) => {
                if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm {
                    let crate::native_software::TargetAdmission::Eligible(
                        crate::native_software::NativeTarget {
                            platform: p,
                            architecture: a,
                            ..
                        },
                    ) = crate::native_software::target_admission_in(tx, &target.device).await?
                    else {
                        return Ok(false);
                    };
                    return v
                        .assignment
                        .authorized_in(&service.admission(), tx, &target.device, p, a, now)
                        .await;
                }
                let Some(binding) = crate::channels::agent_binding_in(
                    tx,
                    service.agent_store.clone(),
                    target.registration,
                )
                .await?
                else {
                    return Ok(false);
                };
                if !v
                    .assignment
                    .supported_in(&service.admission(), tx, &binding)
                    .await?
                {
                    return Ok(false);
                }
                let Some((platform, architecture)) =
                    agent_profile_in(service, tx, target.registration).await?
                else {
                    return Ok(false);
                };
                v.assignment
                    .authorized_in(
                        &service.admission(),
                        tx,
                        &target.device,
                        platform,
                        architecture,
                        now,
                    )
                    .await
            }
        }
    }
    /// Recheck current authority for an existing Run without reselecting rollout.
    pub(crate) async fn run_admission_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        if let Self::Software(v) = self {
            let tenant = tx.tenant_id().to_string();
            let device = target.device.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(rss_mdm_registration_service::lifecycle::work_allowed_in(
                            c, &tenant, &device,
                        )
                        .await)
                    })
                })
                .await??
            {
                return Ok(false);
            }
            let profile = if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm {
                match crate::native_software::target_admission_in(tx, &target.device).await? {
                    crate::native_software::TargetAdmission::Eligible(v) => {
                        Some((v.platform, v.architecture))
                    }
                    crate::native_software::TargetAdmission::ProjectionPending(_)
                    | crate::native_software::TargetAdmission::Rejected(_) => None,
                }
            } else {
                agent_profile_in(service, tx, target.registration).await?
            };
            let Some((platform, architecture)) = profile else {
                return Ok(false);
            };
            return v
                .assignment
                .authorized_run_in(
                    &service.admission(),
                    tx,
                    &target.device,
                    platform,
                    architecture,
                    now,
                )
                .await;
        }
        match self {
            Self::Script(v) => Ok(v.active
                && crate::script_eligibility::require_in(
                    tx,
                    service.agent_store.clone(),
                    target,
                    &v.frozen,
                )
                .await?),
            Self::Native(v) => Ok(v.active),
            Self::AgentCollection(v) => Ok(v.active
                && v.frozen.authorized_in(tx, target, now).await?
                && crate::agent_collection_eligibility::check_in(
                    tx,
                    service.agent_store.clone(),
                    target,
                    v.frozen.input.platform,
                    v.frozen.input.architecture,
                    &v.frozen.definition,
                )
                .await?),
            Self::Credential(v) => Ok(v.active
                && v.frozen.authorized_in(service, tx, target, now).await?
                && crate::credential_tasks::eligible(
                    service,
                    tx,
                    target,
                    v.frozen.input.architecture,
                )
                .await?),
            Self::Enrollment(v) => v.accepted_in(service, tx, target).await,
            Self::DeviceAccess(v) => v.allowed_in(service, tx, target).await,
            Self::Retirement(v) => v.allowed_in(tx, target, None).await,
            Self::Software(_) => unreachable!(),
        }
    }
    pub async fn authorized_run_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        run: &Run,
        now: i64,
    ) -> Result<bool> {
        if let Self::Retirement(v) = self {
            return v.allowed_in(tx, &run.target, Some(run.id)).await;
        }
        if let Self::DeviceAccess(v) = self {
            return v.allowed_in(service, tx, &run.target).await;
        }
        if let Self::Software(v) = self
            && let Some(retirement) = v.assignment.retirement
        {
            if !crate::unmanage::cleanup_allowed_in(
                tx,
                retirement,
                &run.target.device,
                Some(run.id),
            )
            .await?
            {
                return Ok(false);
            }
            return self.run_admission_in(service, tx, &run.target, now).await;
        }
        if run.state.started_at.is_none() {
            let channel = if matches!(self, Self::Native(_))
                || matches!(self, Self::Software(v) if v.assignment.channel()==rss_mdm_inventory::Channel::Mdm)
            {
                rss_mdm_inventory::Channel::Mdm
            } else {
                rss_mdm_inventory::Channel::Agent
            };
            let source = service.source.clone();
            let tenant = tx.tenant_id();
            let device = run.target.device.clone();
            let evidence = run.source_objects.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .evidence_valid_on(c, tenant, channel, &device, &evidence)
                            .await)
                    })
                })
                .await??
            {
                return Ok(false);
            }
        }
        match &run.invocation {
            Some(invocation) => {
                invocation
                    .valid_in(service, tx, self, &run.target, now)
                    .await
            }
            None if matches!(self, Self::Software(v) if v.assignment.intent() == rss_mdm_policy::SoftwareIntent::AvailableInstall) => {
                Ok(false)
            }
            None => self.run_admission_in(service, tx, &run.target, now).await,
        }
    }

    /// Completion keeps current business authority without requiring a fresh executor context.
    /// Capability and OS helper admission remains mandatory for every new Offer and Start.
    pub async fn completion_authorized_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        match self {
            Self::Credential(v) => {
                return Ok(v.active && v.frozen.authorized_in(service, tx, target, now).await?);
            }
            Self::AgentCollection(v) => {
                return Ok(v.active && v.frozen.authorized_in(tx, target, now).await?);
            }
            Self::Script(v) => return Ok(v.active),
            Self::Native(v) => return Ok(v.active),
            Self::Enrollment(v) => return Ok(v.policy.state.is_enabled()),
            _ => (),
        }
        if let Self::Software(v) = self {
            if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm {
                let crate::native_software::TargetAdmission::Eligible(
                    crate::native_software::NativeTarget {
                        platform: p,
                        architecture: a,
                        ..
                    },
                ) = crate::native_software::target_admission_in(tx, &target.device).await?
                else {
                    return Ok(false);
                };
                return Ok(v
                    .assignment
                    .admitted_in(&service.admission(), tx, p, a)
                    .await?
                    .is_some());
            }
            let Some((platform, architecture)) =
                agent_profile_in(service, tx, target.registration).await?
            else {
                return Ok(false);
            };
            v.assignment
                .authorized_run_in(
                    &service.admission(),
                    tx,
                    &target.device,
                    platform,
                    architecture,
                    now,
                )
                .await
        } else {
            self.authorized_in(service, tx, target, now).await
        }
    }
    pub async fn withdrawn_in(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        match self {
            Self::DeviceAccess(v) => Ok(!v.allowed_in(service, tx, target).await?),
            Self::Retirement(v) => Ok(!v.allowed_in(tx, target, None).await?),
            Self::Credential(v) => Ok(v.withdrawn_in(&service.source, tx, &target.device).await?
                || !v.frozen.authorized_in(service, tx, target, now).await?),
            Self::AgentCollection(v) => {
                Ok(v.withdrawn_in(&service.source, tx, &target.device).await?
                    || !v.frozen.authorized_in(tx, target, now).await?)
            }
            Self::Script(v) => v.withdrawn_in(&service.source, tx, &target.device).await,
            Self::Native(v) => v.withdrawn_in(&service.source, tx, &target.device).await,
            Self::Software(v) if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm => {
                match crate::native_software::target_admission_in(tx, &target.device).await? {
                    crate::native_software::TargetAdmission::Eligible(current)
                    | crate::native_software::TargetAdmission::ProjectionPending(current) => {
                        // Pending evidence can deny authority, never authorize a new side effect.
                        Ok(current.target.registration != target.registration
                            || current.target.generation != target.generation
                            || !v
                                .assignment
                                .authorized_run_in(
                                    &service.admission(),
                                    tx,
                                    &target.device,
                                    current.platform,
                                    current.architecture,
                                    now,
                                )
                                .await?)
                    }
                    crate::native_software::TargetAdmission::Rejected(_) => Ok(true),
                }
            }
            Self::Software(_) | Self::Enrollment(_) => Ok(!self
                .completion_authorized_in(service, tx, target, now)
                .await?),
        }
    }
    pub async fn task(
        &self,
        service: &crate::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<rss_mdm_agent_wire::runtime::TaskPayload> {
        match self {
            Self::DeviceAccess(v) => v.task(service, tx, target, issue).await,
            Self::Retirement(v) => v.task(service, tx, target, issue).await,
            Self::Credential(v) => {
                crate::credential_tasks::task(v, service, tx, target, issue).await
            }
            Self::Enrollment(v) => v.task(service, tx, target, issue).await,
            Self::Native(_) => Err(Error::Unsupported.into()),
            Self::AgentCollection(v) => {
                use rss_mdm_agent_wire::runtime as wire;
                let run = load_run(tx, issue.run).await?;
                let plan = v.frozen.definition.spec().plan.clone();
                let binding = crate::channels::agent_binding_in(
                    tx,
                    service.agent_store.clone(),
                    target.registration,
                )
                .await?
                .ok_or(Error::Forbidden)?;
                let execution = checked_input(wire::NativeExecutionBinding::bind(
                    &plan,
                    &binding.execution_context,
                ))?;
                let spec = wire::CollectionTaskSpec {
                    fields: v
                        .frozen
                        .fields
                        .iter()
                        .map(rss_mdm_inventory_service::collection::wire::to_wire_field)
                        .collect::<std::result::Result<_, _>>()
                        .map_err(|_| Error::Malformed)?,
                    mappings: v.frozen.definition.spec().mappings.clone(),
                    wire_version: wire::COLLECTION_TASK_VERSION,
                    execution,
                    tenant_id: checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                    device_id: target.device.clone(),
                    registration_id: target.registration,
                    generation: target.generation.try_into().map_err(|_| Error::Malformed)?,
                    platform: plan.platform(),
                    architecture: match v.frozen.input.architecture {
                        rss_mdm_policy::Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                        rss_mdm_policy::Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
                    },
                    task_id: issue.run,
                    attempt_id: issue.attempt,
                    permit: issue.permit,
                    expires_at: issue.expiry,
                    deadline: run.deadline,
                    resource: v.frozen.resource.clone(),
                    resource_digest: v.frozen.resource_digest,
                    authorization: wire::TaskAuthorization::Policy {
                        policy_id: v.owner,
                        policy_version: v.id,
                    },
                    plan_digest: plan.digest(),
                    plan,
                };
                checked_input(spec.validate())?;
                Ok(wire::TaskPayload::Collection(Box::new(spec)))
            }
            Self::Script(v) => {
                use rss_mdm_agent_wire::runtime as wire;
                let run = load_run(tx, issue.run).await?;
                let (authorization, parameters) = if let Some(invocation) = &run.invocation {
                    (
                        invocation.authorization.clone(),
                        invocation.parameters.clone(),
                    )
                } else {
                    let authorization = wire::TaskAuthorization::Policy {
                        policy_id: v.owner,
                        policy_version: v.id,
                    };
                    (
                        authorization,
                        checked_input(serde_json::from_value(
                            v.frozen.parameters.resolve(&serde_json::json!({}))?,
                        ))?,
                    )
                };
                Ok(v.frozen.task(
                    checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                    target,
                    issue.run,
                    issue.attempt,
                    issue.permit,
                    issue.expiry,
                    authorization,
                    parameters,
                    run.deadline,
                    &crate::channels::agent_binding_in(
                        tx,
                        service.agent_store.clone(),
                        target.registration,
                    )
                    .await?
                    .ok_or(Error::Forbidden)?
                    .execution_context,
                )?)
            }
            Self::Software(v) => {
                use rss_mdm_agent_wire::runtime as wire;
                let (platform, architecture) = agent_profile_in(service, tx, target.registration)
                    .await?
                    .ok_or(Error::Forbidden)?;
                let binding = crate::channels::agent_binding_in(
                    tx,
                    service.agent_store.clone(),
                    target.registration,
                )
                .await?
                .ok_or(Error::Forbidden)?;
                let steps = v
                    .assignment
                    .prepared_in(
                        &service.admission(),
                        tx,
                        platform,
                        architecture,
                        &binding.execution_context,
                    )
                    .await?
                    .ok_or(Error::Forbidden)?;
                let plan_bytes = checked_input(serde_json::to_vec(&steps))?;
                let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &plan_bytes)
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::Malformed)?;
                let run = load_run(tx, issue.run).await?;
                let authorization = run
                    .invocation
                    .as_ref()
                    .map(|i| i.authorization.clone())
                    .unwrap_or(wire::TaskAuthorization::Policy {
                        policy_id: v.owner,
                        policy_version: v.id,
                    });
                let spec = wire::SoftwareTaskSpec {
                    wire_version: wire::WIRE_VERSION,
                    tenant_id: checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                    device_id: target.device.clone(),
                    platform: match platform {
                        rss_mdm_policy::Platform::Windows => wire::TaskPlatform::Windows,
                        rss_mdm_policy::Platform::Macos => wire::TaskPlatform::Macos,
                    },
                    architecture: match architecture {
                        rss_mdm_policy::Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                        rss_mdm_policy::Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
                    },
                    registration_id: target.registration,
                    generation: target.generation.try_into().map_err(|_| Error::Malformed)?,
                    task_id: issue.run,
                    attempt_id: issue.attempt,
                    permit: issue.permit,
                    expires_at: issue.expiry,
                    steps,
                    execution_context: binding.execution_context,
                    authorization,
                    definition_digest: digest,
                    intent: match v.assignment.intent() {
                        rss_mdm_policy::SoftwareIntent::RequiredInstall
                        | rss_mdm_policy::SoftwareIntent::AvailableInstall => {
                            wire::SoftwareTaskIntent::Install
                        }
                        rss_mdm_policy::SoftwareIntent::ExplicitUninstall => {
                            wire::SoftwareTaskIntent::Uninstall
                        }
                    },
                };
                checked_input(spec.try_into())
            }
        }
    }
}
pub async fn agent_profile_in(
    service: &crate::ExecutionService,
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    let profile = crate::channels::agent_binding_in(tx, service.agent_store.clone(), registration)
        .await?
        .map(|b| (b.platform, b.architecture));
    profile
        .map(|(platform, architecture)| {
            let platform = match platform.as_str() {
                "windows" => rss_mdm_policy::Platform::Windows,
                "macos" => rss_mdm_policy::Platform::Macos,
                _ => return Err(Error::Unavailable(crate::Failure::CommandInvariant).into()),
            };
            let architecture = match architecture.as_str() {
                "x86_64" => rss_mdm_policy::Architecture::X86_64,
                "aarch64" => rss_mdm_policy::Architecture::Aarch64,
                _ => return Err(Error::Unavailable(crate::Failure::CommandInvariant).into()),
            };
            Ok((platform, architecture))
        })
        .transpose()
}
pub async fn load_policy_version(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<ScheduledPolicy> {
    let (policy, frozen) = crate::sources::storage::version_in(reader, tx, id).await?;
    match frozen {
        crate::frozen::Frozen::DeviceAccess { .. } => Err(Error::Unsupported.into()),
        crate::frozen::Frozen::UnmanageDevice {
            run_lifetime_seconds,
            ..
        } => Ok(ScheduledPolicy::Retirement(
            crate::unmanage::RetirementPlan {
                owner: policy.id,
                version: id,
                lifetime: run_lifetime_seconds,
            },
        )),
        crate::frozen::Frozen::Credential { .. } => Ok(ScheduledPolicy::Credential(
            crate::sources::admission::credential_in(reader, tx, id).await?,
        )),
        crate::frozen::Frozen::MdmEnrollment { action } => Ok(ScheduledPolicy::Enrollment(
            crate::sources::enrollment::EnrollmentPolicy {
                id,
                owner: policy.id,
                policy,
                frozen: *action,
            },
        )),
        crate::frozen::Frozen::AgentCollection { .. } => Ok(ScheduledPolicy::AgentCollection(
            crate::sources::admission::agent_collection_in(reader, tx, id).await?,
        )),
        crate::frozen::Frozen::NativeCollection { .. } => Ok(ScheduledPolicy::Native(
            crate::sources::admission::native_in(reader, tx, id).await?,
        )),
        crate::frozen::Frozen::Execution { .. } => Ok(ScheduledPolicy::Script(Box::new(
            crate::sources::admission::read_in(reader, tx, id).await?,
        ))),
        crate::frozen::Frozen::Software { .. } => Ok(ScheduledPolicy::Software(
            crate::sources::software::read_in(reader, tx, id).await?,
        )),
        _ => Err(Error::Unsupported.into()),
    }
}

pub async fn load_source(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    source: Source,
) -> Result<ScheduledPolicy> {
    match source {
        Source::DeviceAccess { delivery, .. } => Ok(ScheduledPolicy::DeviceAccess(
            crate::device_access::load(tx, delivery).await?,
        )),
        Source::Policy { version } => load_policy_version(reader, tx, version).await,
        Source::RetirementSoftware {
            version,
            retirement,
        } => Ok(ScheduledPolicy::Software(
            crate::sources::software::retirement_in(reader, tx, version, retirement).await?,
        )),
    }
}
