use super::model::Target;
use super::state::RunState;
use crate::Error;
use crate::execution::{Result, checked_input, storage, stored};
use crate::planning::policies::admission::ExecutionPolicy;
use crate::planning::policies::software::SoftwareExecutionPolicy;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Policy { version: Uuid },
    RemoteOperation { operation: Uuid },
}
impl Source {
    pub fn columns(self) -> (&'static str, Option<Uuid>, Option<Uuid>) {
        match self {
            Self::Policy { version } => ("policy", Some(version), None),
            Self::RemoteOperation { operation } => ("remote_operation", None, Some(operation)),
        }
    }
    pub fn audit(self, audit: &rss_mdm_audit_integration::RequestAudit) {
        if let Self::Policy { version } = self {
            audit.plan(version);
        }
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
}
pub async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT source_kind,policy_version,remote_operation,device,registration::text,generation,available_at,deadline,state,result FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::Execution(crate::execution::error::ExecutionError::MissingTask))?;
    Ok(Run {
        id,
        source: match row.try_get::<&str, _>("source_kind")? {
            "policy" => Source::Policy {
                version: row.try_get("policy_version")?,
            },
            "remote_operation" => Source::RemoteOperation {
                operation: row.try_get("remote_operation")?,
            },
            _ => return Err(Error::Unavailable(crate::Failure::CommandInvariant).into()),
        },
        target: Target {
            device: row.try_get("device")?,
            registration: stored(Uuid::parse_str(&row.try_get::<String, _>("registration")?))?,
            generation: row.try_get("generation")?,
        },
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        state: stored(serde_json::from_value(row.try_get("state")?))?,
        result: row.try_get("result")?,
    })
}
pub async fn save_run(tx: &mut PgTransaction<'_>, run: &Run) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id.to_string();
    let state = checked_input(serde_json::to_value(&run.state))?;
    let result = run.result.clone();
    let changed = tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4)").bind(tenant).bind(id).bind(state).bind(result).execute(c).await})).await?;
    if changed.rows_affected() > 0 {
        crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
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
    Script(ExecutionPolicy),
    Software(SoftwareExecutionPolicy),
    Enrollment(crate::planning::policies::enrollment::EnrollmentPolicy),
}
pub struct TaskIssue {
    pub run: Uuid,
    pub attempt: Uuid,
    pub permit: rss_mdm_agent_wire::TaskPermit,
    pub expiry: i64,
}
impl ScheduledPolicy {
    pub fn owner(&self) -> Uuid {
        match self {
            Self::Script(v) => v.owner,
            Self::Software(v) => v.owner,
            Self::Enrollment(v) => v.owner,
        }
    }
    pub fn timeout_seconds(&self) -> u32 {
        match self {
            Self::Script(v) => v.frozen.definition.spec().timeout_seconds,
            Self::Software(v) => v.frozen.run_lifetime_seconds,
            Self::Enrollment(v) => v.frozen.run_lifetime_seconds,
        }
    }
    pub async fn authorized_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        match self {
            Self::Script(v) => v.authorized_in(tx, &target.device, now).await,
            Self::Enrollment(v) => v.authorized_in(service, tx, target, now).await,
            Self::Software(v) => {
                let Some(binding) = crate::execution::channels::agent_binding_in(
                    tx,
                    service.agent_store.clone(),
                    target.registration,
                )
                .await?
                else {
                    return Ok(false);
                };
                if !v.supported_in(service, tx, &binding).await? {
                    return Ok(false);
                }
                let Some((platform, architecture)) =
                    agent_profile_in(service, tx, target.registration).await?
                else {
                    return Ok(false);
                };
                v.authorized_in(service, tx, &target.device, platform, architecture, now)
                    .await
            }
        }
    }
    pub async fn withdrawn_in(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        match self {
            Self::Script(v) => v.withdrawn_in(tx, &target.device).await,
            Self::Software(_) | Self::Enrollment(_) => {
                Ok(!self.authorized_in(service, tx, target, now).await?)
            }
        }
    }
    pub async fn task(
        &self,
        service: &crate::execution::ExecutionService,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<rss_mdm_agent_wire::TaskPayload> {
        match self {
            Self::Enrollment(v) => v.task(service, tx, target, issue).await,
            Self::Script(v) => Ok(v.frozen.task(
                checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                target,
                issue.run,
                issue.attempt,
                issue.permit,
                issue.expiry,
            )?),
            Self::Software(v) => {
                use rss_mdm_agent_wire as wire;
                let (platform, architecture) = agent_profile_in(service, tx, target.registration)
                    .await?
                    .ok_or(Error::Forbidden)?;
                let binding = crate::execution::channels::agent_binding_in(
                    tx,
                    service.agent_store.clone(),
                    target.registration,
                )
                .await?
                .ok_or(Error::Forbidden)?;
                let task_platform = match platform {
                    rss_mdm_policy::Platform::Windows => wire::TaskPlatform::Windows,
                    rss_mdm_policy::Platform::Macos => wire::TaskPlatform::Macos,
                };
                let selected_steps = v
                    .execution_steps_in(service, tx, platform, architecture)
                    .await?
                    .ok_or(Error::Forbidden)?;
                let mut steps = Vec::new();
                for (index, selected) in selected_steps.iter().enumerate() {
                    let variant = selected
                        .version()
                        .resolve(
                            selected.platform(),
                            selected.architecture(),
                            selected.variant(),
                        )
                        .map_err(|_| Error::Malformed)?;
                    let rss_mdm_resource::Declaration::Software { definition } =
                        variant.declaration()
                    else {
                        return Err(Error::Malformed.into());
                    };
                    let action = super::software_wire::software_action(definition.spec());
                    let export = super::software_exports::for_step_in(
                        service,
                        tx,
                        &v.frozen.delivery,
                        selected,
                        &action,
                    )
                    .await?;
                    steps.push(
                        super::software_wire::software_step(
                            definition.spec(),
                            index,
                            task_platform,
                            &binding.execution_context,
                            export,
                        )
                        .map_err(|_| Error::Forbidden)?,
                    );
                }
                let plan_bytes = checked_input(serde_json::to_vec(&steps))?;
                let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &plan_bytes)
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::Malformed)?;
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
                    definition_digest: digest,
                    intent: match v.intent() {
                        rss_mdm_policy::SoftwareIntent::RequiredInstall
                        | rss_mdm_policy::SoftwareIntent::AvailableInstall => {
                            wire::SoftwareTaskIntent::Install
                        }
                        rss_mdm_policy::SoftwareIntent::ExplicitUninstall => {
                            wire::SoftwareTaskIntent::Uninstall
                        }
                    },
                    start_mode: if matches!(
                        v.intent(),
                        rss_mdm_policy::SoftwareIntent::AvailableInstall
                    ) {
                        wire::SoftwareStartMode::UserInitiated
                    } else {
                        wire::SoftwareStartMode::Automatic
                    },
                };
                checked_input(spec.try_into())
            }
        }
    }
}
pub async fn agent_profile_in(
    service: &crate::execution::ExecutionService,
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    let profile =
        crate::execution::channels::agent_binding_in(tx, service.agent_store.clone(), registration)
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
    let (policy, frozen) = crate::planning::policies::storage::version_in(reader, tx, id).await?;
    match frozen {
        crate::planning::policies::Frozen::MdmEnrollment { action } => Ok(
            ScheduledPolicy::Enrollment(crate::planning::policies::enrollment::EnrollmentPolicy {
                id,
                owner: policy.id,
                policy,
                frozen: *action,
            }),
        ),
        crate::planning::policies::Frozen::Execution { .. } => Ok(ScheduledPolicy::Script(
            crate::planning::policies::admission::read_in(reader, tx, id).await?,
        )),
        crate::planning::policies::Frozen::Software { .. } => Ok(ScheduledPolicy::Software(
            crate::planning::policies::software::read_in(reader, tx, id).await?,
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
        Source::Policy { version } => load_policy_version(reader, tx, version).await,
        Source::RemoteOperation { operation } => Ok(ScheduledPolicy::Script(
            crate::planning::policies::admission::remote_in(tx, operation).await?,
        )),
    }
}
