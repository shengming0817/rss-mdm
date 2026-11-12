use crate::deployment::Error;
use crate::deployment::Target;
use crate::deployment::sources::software::SoftwareExecutionPolicy;
use crate::deployment::{Result, checked_input, storage, stored};
use rss_mdm_task_state::RunState;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Policy { version: Uuid },
    RetirementSoftware { version: Uuid, retirement: Uuid },
}
impl Source {
    pub fn columns(self) -> (&'static str, Uuid) {
        match self {
            Self::Policy { version } => ("policy", version),
            Self::RetirementSoftware { version, .. } => ("retirement", version),
        }
    }
    pub fn audit(self, audit: &rss_mdm_audit_integration::RequestAudit) {
        let (_, version) = self.columns();
        audit.plan(version);
    }
}
pub struct Run {
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    pub retirement: Option<Uuid>,
    pub id: Uuid,
    pub source: Source,
    pub target: Target,
    pub available_at: i64,
    pub deadline: i64,
    pub state: RunState,
    pub result: Option<super::result::RunResult>,
    pub invocation: Option<crate::deployment::self_service::Invocation>,
    pub source_objects: Vec<crate::deployment::scope::DeviceObject>,
}
pub async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, true).await
}
pub async fn read_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, false).await
}
async fn run_in(tx: &mut PgTransaction<'_>, id: Uuid, locked: bool) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{if locked {sqlx::query("SELECT id FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(&tenant).bind(id).fetch_optional(&mut *c).await?;}sqlx::query("SELECT a.retirement, a.origin, a.source_kind, a.policy_version, a.device, a.available_at, a.deadline, a.state, a.result, a.invocation, a.source_objects FROM mdm_software_deployment.action_runs AS a WHERE a.tenant_id = CAST($1 AS uuid) AND a.id = CAST($2 AS uuid)").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::Execution(crate::deployment::missing::ExecutionError::MissingTask))?;
    Ok(Run {
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        retirement: row.try_get("retirement")?,
        id,
        source: match row.try_get::<&str, _>("source_kind")? {
            "policy" => Source::Policy {
                version: row.try_get("policy_version")?,
            },
            "retirement" => Source::RetirementSoftware {
                version: row.try_get("policy_version")?,
                retirement: row.try_get("retirement")?,
            },
            _ => {
                return Err(
                    Error::Unavailable(crate::deployment::Failure::CommandInvariant).into(),
                );
            }
        },
        target: Target {
            device: row.try_get::<uuid::Uuid, _>("device").and_then(|id| {
                rss_mdm_agent_wire::DeviceId::try_from(id)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })?,
        },
        source_objects: stored(serde_json::from_value(row.try_get("source_objects")?))?,
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        state: stored(serde_json::from_value(row.try_get("state")?))?,
        result: row
            .try_get::<Option<Value>, _>("result")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
        invocation: row
            .try_get::<Option<Value>, _>("invocation")?
            .map(serde_json::from_value)
            .map(crate::deployment::stored)
            .transpose()?,
    })
}
pub async fn save_run(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    run: &Run,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id.to_string();
    let state = checked_input(serde_json::to_value(&run.state))?;
    let result = run
        .result
        .as_ref()
        .map(|v| stored(serde_json::to_value(v)))
        .transpose()?;
    let previous=tx.with_connection({let tenant=tenant.clone();let id=id.clone();move|c|Box::pin(async move {sqlx::query_scalar::<_,Value>("SELECT state FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).fetch_one(c).await})}).await?;
    let changed = tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_software_deployment.action_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4)").bind(tenant).bind(id).bind(state).bind(result).execute(c).await})).await?;
    if changed.rows_affected() > 0 {
        if let Source::Policy { version } = run.source
            && let Some(verified) =
                super::scheduled::VerifiedSoftwareVersion::verify_in(reader, tx, version).await?
        {
            super::scheduled::wake_in(
                reconcile,
                tx,
                &verified,
                &super::scheduled::Work {
                    version,
                    device: run.target.device,
                },
            )
            .await?;
        }
        crate::deployment::worker_wake::notify_in(
            tx,
            crate::deployment::worker_wake::Work::CommandRecovery,
        )
        .await?;
    }
    let terminal = match run.state.execution {
        rss_mdm_task_state::Execution::Succeeded => Some("succeeded"),
        rss_mdm_task_state::Execution::Failed => Some("failed"),
        _ if run.state.cancellation == rss_mdm_task_state::Cancellation::Confirmed => {
            Some("cancelled")
        }
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
                occurred_at: crate::deployment::storage::now(tx).await?,
                tenant_id: stored(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                device_id: run.target.device,
                data: EventData::Policy {
                    run_id: run.id,
                    policy_version: version,
                    device_id: run.target.device,

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
    storage::lock_action_request(tx, actor, id).await?;
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT fingerprint,response FROM mdm_software_deployment.action_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_optional(c).await})).await?;
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
    target: &crate::deployment::Target,
    audit_details: Option<Value>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let response = response.clone();
    let target = target.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_software_deployment.action_receipts (tenant_id, actor, id, fingerprint, response, audit_details, device) VALUES (CAST($1 AS uuid), $2, CAST($3 AS uuid), $4, $5, $6, $7)").bind(tenant).bind(actor).bind(id.to_string()).bind(fingerprint).bind(response).bind(audit_details).bind(target.device.into_uuid()).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn audit_details(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT audit_details FROM mdm_software_deployment.action_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_one(c).await})).await.map_err(Into::into)
}

pub enum ScheduledPolicy {
    Software(SoftwareExecutionPolicy),
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
            Self::Software(v) => v.owner,
        }
    }
    pub(crate) async fn authorized_in(
        &self,
        service: &crate::deployment::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        if let Self::Software(v) = self
            && v.assignment.retirement.is_some()
        {
            let Some((platform, architecture)) =
                agent_profile_in(service, tx, target.device).await?
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
        let device = target.device;
        let allowed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_registration_service::lifecycle::work_allowed_in(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        c,
                        &tenant,
                        &device,
                    )
                    .await)
                })
            })
            .await??;
        if !allowed {
            return Ok(false);
        }
        match self {
            Self::Software(v) => {
                if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm {
                    let crate::deployment::native_software::TargetAdmission::Eligible(
                        crate::deployment::native_software::NativeTarget {
                            platform: p,
                            architecture: a,
                            ..
                        },
                    ) = crate::deployment::native_software::target_admission_in(
                        service.inventory.clone(),
                        tx,
                        &target.device,
                    )
                    .await?
                    else {
                        return Ok(false);
                    };
                    return v
                        .assignment
                        .authorized_in(&service.admission(), tx, &target.device, p, a, now)
                        .await;
                }
                let Some(binding) = crate::deployment::agent_facts::agent_binding_in(
                    tx,
                    service.agent_store.clone(),
                    target.device,
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
                    agent_profile_in(service, tx, target.device).await?
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
        service: &crate::deployment::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        {
            let Self::Software(v) = self;
            let tenant = tx.tenant_id().to_string();
            let device = target.device;
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(rss_mdm_registration_service::lifecycle::work_allowed_in(
                            rss_mdm_install_support::StorageProfile::Mdm,
                            c,
                            &tenant,
                            &device,
                        )
                        .await)
                    })
                })
                .await??
            {
                return Ok(false);
            }
            let profile = if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm {
                match crate::deployment::native_software::target_admission_in(
                    service.inventory.clone(),
                    tx,
                    &target.device,
                )
                .await?
                {
                    crate::deployment::native_software::TargetAdmission::Eligible(v) => {
                        Some((v.platform, v.architecture))
                    }
                    crate::deployment::native_software::TargetAdmission::ProjectionPending(_)
                    | crate::deployment::native_software::TargetAdmission::Rejected(_) => None,
                }
            } else {
                agent_profile_in(service, tx, target.device).await?
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
    }
    pub(crate) async fn authorized_run_in(
        &self,
        service: &crate::deployment::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        run: &Run,
        now: i64,
    ) -> Result<bool> {
        if let Self::Software(v) = self
            && let Some(retirement) = v.assignment.retirement
        {
            if !crate::deployment::retirement::cleanup_allowed_in(
                service.lifecycle.clone(),
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
            let channel = if matches!(self, Self::Software(v) if v.assignment.channel()==rss_mdm_inventory::Channel::Mdm)
            {
                rss_mdm_inventory::Channel::Mdm
            } else {
                rss_mdm_inventory::Channel::Agent
            };
            let source = service.source.clone();
            let tenant = tx.tenant_id();
            let device = run.target.device;
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
    pub(crate) async fn completion_authorized_in(
        &self,
        service: &crate::deployment::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        {
            let Self::Software(v) = self;
            if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm {
                let crate::deployment::native_software::TargetAdmission::Eligible(
                    crate::deployment::native_software::NativeTarget {
                        platform: p,
                        architecture: a,
                        ..
                    },
                ) = crate::deployment::native_software::target_admission_in(
                    service.inventory.clone(),
                    tx,
                    &target.device,
                )
                .await?
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
                agent_profile_in(service, tx, target.device).await?
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
        }
    }
    pub(crate) async fn withdrawn_in(
        &self,
        service: &crate::deployment::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        match self {
            Self::Software(v) if v.assignment.channel() == rss_mdm_inventory::Channel::Mdm => {
                match crate::deployment::native_software::target_admission_in(
                    service.inventory.clone(),
                    tx,
                    &target.device,
                )
                .await?
                {
                    crate::deployment::native_software::TargetAdmission::Eligible(current)
                    | crate::deployment::native_software::TargetAdmission::ProjectionPending(
                        current,
                    ) => {
                        // Pending evidence can deny authority, never authorize a new side effect.
                        Ok(current.target.device != target.device
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
                    crate::deployment::native_software::TargetAdmission::Rejected(_) => Ok(true),
                }
            }
            Self::Software(_) => Ok(!self
                .completion_authorized_in(service, tx, target, now)
                .await?),
        }
    }
    pub(crate) async fn task(
        &self,
        service: &crate::deployment::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<rss_mdm_agent_wire::runtime::TaskPayload> {
        match self {
            Self::Software(v) => {
                use rss_mdm_agent_wire::runtime as wire;
                let (platform, architecture) = agent_profile_in(service, tx, target.device)
                    .await?
                    .ok_or(Error::Forbidden)?;
                let binding = crate::deployment::agent_facts::agent_binding_in(
                    tx,
                    service.agent_store.clone(),
                    target.device,
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
                    device_id: target.device,
                    platform: match platform {
                        rss_mdm_policy::Platform::Windows => wire::TaskPlatform::Windows,
                        rss_mdm_policy::Platform::Macos => wire::TaskPlatform::Macos,
                    },
                    architecture: match architecture {
                        rss_mdm_policy::Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                        rss_mdm_policy::Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
                    },

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
pub(crate) async fn agent_profile_in(
    service: &crate::deployment::transactions::Transactions,
    tx: &mut PgTransaction<'_>,
    device: rss_mdm_agent_wire::DeviceId,
) -> Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    let profile =
        crate::deployment::agent_facts::agent_binding_in(tx, service.agent_store.clone(), device)
            .await?
            .map(|b| (b.platform, b.architecture));
    profile
        .map(|(platform, architecture)| {
            let platform = match platform.as_str() {
                "windows" => rss_mdm_policy::Platform::Windows,
                "macos" => rss_mdm_policy::Platform::Macos,
                _ => {
                    return Err(
                        Error::Unavailable(crate::deployment::Failure::CommandInvariant).into(),
                    );
                }
            };
            let architecture = match architecture.as_str() {
                "x86_64" => rss_mdm_policy::Architecture::X86_64,
                "aarch64" => rss_mdm_policy::Architecture::Aarch64,
                _ => {
                    return Err(
                        Error::Unavailable(crate::deployment::Failure::CommandInvariant).into(),
                    );
                }
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
    let (_policy, frozen) = crate::deployment::sources::storage::version_in(reader, tx, id).await?;
    match frozen {
        crate::deployment::frozen::Published::Software { .. } => Ok(ScheduledPolicy::Software(
            crate::deployment::sources::software::read_in(reader, tx, id).await?,
        )),
        _ => Err(Error::Unsupported.into()),
    }
}

pub async fn load_source(
    service: &crate::deployment::Transactions,
    tx: &mut PgTransaction<'_>,
    source: Source,
) -> Result<ScheduledPolicy> {
    match source {
        Source::Policy { version } => {
            load_policy_version(&service.policy_reader, tx, version).await
        }
        Source::RetirementSoftware {
            version,
            retirement,
        } => Ok(ScheduledPolicy::Software(
            crate::deployment::sources::software::retirement_in(service, tx, version, retirement)
                .await?,
        )),
    }
}
