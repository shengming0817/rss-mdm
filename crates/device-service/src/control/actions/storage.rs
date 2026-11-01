use crate::control::Error;
use crate::control::Target;

use crate::control::{Result, checked_input, storage, stored};
use rss_mdm_task_state::RunState;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Policy { version: Uuid },
}
impl Source {
    pub fn columns(self) -> (&'static str, Uuid) {
        match self {
            Self::Policy { version } => ("policy", version),
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

    pub source_objects: Vec<rss_mdm_inventory_service::objects::DeviceObject>,
}
pub async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, true).await
}
pub async fn read_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, false).await
}
async fn run_in(tx: &mut PgTransaction<'_>, id: Uuid, locked: bool) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{if locked {sqlx::query("SELECT id FROM mdm_devices.unmanage_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(&tenant).bind(id).fetch_optional(&mut *c).await?;}sqlx::query("SELECT w.operation AS retirement,a.origin,a.source_kind,a.policy_version,a.device,a.registration::text,a.generation,a.available_at,a.deadline,a.state,a.result,a.source_objects FROM mdm_devices.unmanage_runs a LEFT JOIN mdm_devices.retirement_work w ON(w.tenant_id,w.execution)=(a.tenant_id,a.id) LEFT JOIN mdm_devices.retirements o ON(o.tenant_id,o.id)=(w.tenant_id,w.operation) WHERE a.tenant_id=$1::uuid AND a.id=$2::uuid ").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::Execution(crate::control::missing::ExecutionError::MissingTask))?;
    Ok(Run {
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        retirement: row.try_get("retirement")?,
        id,
        source: match row.try_get::<&str, _>("source_kind")? {
            "policy" => Source::Policy {
                version: row.try_get("policy_version")?,
            },
            _ => return Err(Error::Unavailable(crate::control::Failure::CommandInvariant).into()),
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
        result: row
            .try_get::<Option<Value>, _>("result")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
    })
}
pub async fn save_run(
    _reconcile: &rss_reconcile_postgres::PgMessagingStore,
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
    let previous=tx.with_connection({let tenant=tenant.clone();let id=id.clone();move|c|Box::pin(async move {sqlx::query_scalar::<_,Value>("SELECT state FROM mdm_devices.unmanage_runs WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).fetch_one(c).await})}).await?;
    let changed = tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_devices.unmanage_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4)").bind(tenant).bind(id).bind(state).bind(result).execute(c).await})).await?;
    if changed.rows_affected() > 0 {
        crate::control::worker_wake::notify_in(
            tx,
            crate::control::worker_wake::Work::CommandRecovery,
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
    if let (Some(status), Source::Policy { version }) = (terminal, run.source) {
        let old = previous.get("execution").and_then(Value::as_str);
        let cancelled = previous.get("cancellation").and_then(Value::as_str) == Some("confirmed");
        if old != Some(status) && !(status == "cancelled" && cancelled) {
            use rss_mdm_webhook_service::{events, model::*};
            let event = Event {
                event_id: events::identity(run.id, &format!("terminal:{status}")),
                event_type: EventType::PolicyTerminal,
                version: 1,
                occurred_at: crate::control::storage::now(tx).await?,
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
    storage::lock_action_request(tx, actor, id).await?;
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT fingerprint,response FROM mdm_devices.unmanage_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_optional(c).await})).await?;
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
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_devices.unmanage_receipts(tenant_id,actor,id,fingerprint,response,audit_details) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)").bind(tenant).bind(actor).bind(id.to_string()).bind(fingerprint).bind(response).bind(audit_details).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn audit_details(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT audit_details FROM mdm_devices.unmanage_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_one(c).await})).await.map_err(Into::into)
}

pub enum ScheduledPolicy {
    Retirement(crate::control::unmanage::RetirementPlan),
}
pub struct TaskIssue {
    pub run: Uuid,
    pub attempt: Uuid,
    pub permit: rss_mdm_agent_wire::runtime::TaskPermit,
    pub expiry: i64,
}
impl ScheduledPolicy {
    pub fn owner(&self) -> Uuid {
        let Self::Retirement(v) = self;
        v.owner
    }
    pub(crate) async fn authorized_in(
        &self,
        _service: &crate::control::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        _now: i64,
    ) -> Result<bool> {
        let Self::Retirement(v) = self;
        v.allowed_in(tx, target, None).await
    }
    pub(crate) async fn authorized_run_in(
        &self,
        _service: &crate::control::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        run: &Run,
        _now: i64,
    ) -> Result<bool> {
        let Self::Retirement(v) = self;
        v.allowed_in(tx, &run.target, Some(run.id)).await
    }
    pub(crate) async fn completion_authorized_in(
        &self,
        service: &crate::control::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        self.authorized_in(service, tx, target, now).await
    }
    pub(crate) async fn withdrawn_in(
        &self,
        service: &crate::control::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        Ok(!self.authorized_in(service, tx, target, now).await?)
    }
    pub(crate) async fn task(
        &self,
        service: &crate::control::transactions::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: TaskIssue,
    ) -> Result<rss_mdm_agent_wire::runtime::TaskPayload> {
        let Self::Retirement(v) = self;
        v.task(service, tx, target, issue).await
    }
}
pub(crate) async fn agent_profile_in(
    service: &crate::control::transactions::Transactions,
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    let profile = crate::control::agent_facts::agent_binding_in(
        tx,
        service.agent_store.clone(),
        registration,
    )
    .await?
    .map(|b| (b.platform, b.architecture));
    profile
        .map(|(platform, architecture)| {
            let platform = match platform.as_str() {
                "windows" => rss_mdm_policy::Platform::Windows,
                "macos" => rss_mdm_policy::Platform::Macos,
                _ => {
                    return Err(
                        Error::Unavailable(crate::control::Failure::CommandInvariant).into(),
                    );
                }
            };
            let architecture = match architecture.as_str() {
                "x86_64" => rss_mdm_policy::Architecture::X86_64,
                "aarch64" => rss_mdm_policy::Architecture::Aarch64,
                _ => {
                    return Err(
                        Error::Unavailable(crate::control::Failure::CommandInvariant).into(),
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
    let (policy, frozen) = crate::control::sources::storage::version_in(reader, tx, id).await?;
    match frozen {
        crate::control::frozen::Frozen::UnmanageDevice {
            run_lifetime_seconds,
            ..
        } => Ok(ScheduledPolicy::Retirement(
            crate::control::unmanage::RetirementPlan {
                owner: policy.id,
                version: id,
                lifetime: run_lifetime_seconds,
            },
        )),
    }
}

pub async fn load_source(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    source: Source,
) -> Result<ScheduledPolicy> {
    match source {
        Source::Policy { version } => load_policy_version(reader, tx, version).await,
    }
}
