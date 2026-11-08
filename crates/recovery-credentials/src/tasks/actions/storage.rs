//! Access run state and its immutable binding snapshot share one owner and one transaction.
use crate::tasks::*;
use rss_mdm_task_state::RunState;
use sqlx::Row;
pub struct Run {
    pub id: Uuid,
    pub policy_version: Uuid,
    pub target: Target,
    pub material: Option<crate::Binding>,
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    pub available_at: i64,
    pub deadline: i64,
    pub state: RunState,
    pub source_objects: Vec<rss_mdm_registration_service::participants::scope::DeviceObject>,
    pub result: Option<super::result::RunResult>,
}
pub struct TaskIssue {
    pub run: Uuid,
    pub attempt: Uuid,
    pub permit: rss_mdm_agent_wire::runtime::TaskPermit,
    pub expiry: i64,
}
pub async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}
pub async fn load_run(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Run> {
    run_in(profile, tx, id, true).await
}
pub async fn read_run(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Run> {
    run_in(profile, tx, id, false).await
}
async fn run_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    lock: bool,
) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row = tx
        .with_connection(move |c| {
            Box::pin(async move {
                if lock {
                    sqlx::query(
                        crate::storage_profile::sql(profile).tasks_actions_storage_run_in_1,
                    )
                    .bind(&tenant)
                    .bind(id)
                    .fetch_optional(&mut *c)
                    .await?;
                }
                sqlx::query(crate::storage_profile::sql(profile).tasks_actions_storage_run_in_2)
                    .bind(tenant)
                    .bind(id)
                    .fetch_optional(c)
                    .await
            })
        })
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Run {
        id,
        policy_version: row.try_get("policy_version")?,
        material: row
            .try_get::<Option<serde_json::Value>, _>("material_binding")?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| Error::Invariant)?,
        target: Target {
            device: row.try_get("device")?,
        },
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        source_objects: stored(serde_json::from_value(row.try_get("source_objects")?))?,
        state: stored(serde_json::from_value(row.try_get("state")?))?,
        result: row
            .try_get::<Option<serde_json::Value>, _>("result")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
    })
}
pub async fn save_run(
    profile: rss_mdm_install_support::StorageProfile,
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    run: &Run,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id;
    let state = stored(serde_json::to_value(&run.state))?;
    let result = run
        .result
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Invariant)?;
    let previous = tx
        .with_connection({
            let tenant = tenant.clone();
            move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, serde_json::Value>(
                        crate::storage_profile::sql(profile).tasks_actions_storage_save_run_1,
                    )
                    .bind(tenant)
                    .bind(id)
                    .fetch_one(c)
                    .await
                })
            }
        })
        .await?;
    let changed = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).tasks_actions_storage_save_run_2)
                    .bind(tenant)
                    .bind(id)
                    .bind(state)
                    .bind(result)
                    .execute(c)
                    .await
            })
        })
        .await?;
    if changed.rows_affected() > 0 {
        crate::tasks::wake::run_in(profile, reconcile, tx, id).await?;
    }
    let terminal = match run.state.execution {
        rss_mdm_task_state::Execution::Succeeded => Some("succeeded"),
        rss_mdm_task_state::Execution::Failed => Some("failed"),
        _ if run.state.cancellation == rss_mdm_task_state::Cancellation::Confirmed => {
            Some("cancelled")
        }
        _ => None,
    };
    if let Some(status) = terminal {
        let version = run.policy_version;
        let old = previous
            .get("execution")
            .and_then(serde_json::Value::as_str);
        let cancelled = previous
            .get("cancellation")
            .and_then(serde_json::Value::as_str)
            == Some("confirmed");
        if old != Some(status) && !(status == "cancelled" && cancelled) {
            use rss_mdm_webhook_service::{events, model::*};
            let event = Event {
                event_id: events::identity(run.id, &format!("terminal:{status}")),
                event_type: EventType::PolicyTerminal,
                version: 1,
                occurred_at: now(tx).await?,
                tenant_id: stored(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                device_id: run.target.device.clone(),
                data: EventData::Policy {
                    run_id: run.id,
                    policy_version: version,
                    device_id: run.target.device.to_string(),

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
pub async fn agent_profile_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    registration: String,
) -> Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    Ok(
        agent_facts::agent_binding_in(tx, service.agent_store.clone(), registration)
            .await?
            .and_then(|b| {
                let platform = match b.platform.as_str() {
                    "windows" => rss_mdm_policy::Platform::Windows,
                    "macos" => rss_mdm_policy::Platform::Macos,
                    _ => return None,
                };
                let arch = match b.architecture.as_str() {
                    "x86_64" => rss_mdm_policy::Architecture::X86_64,
                    "aarch64" => rss_mdm_policy::Architecture::Aarch64,
                    _ => return None,
                };
                Some((platform, arch))
            }),
    )
}
pub async fn owned_ids_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    ids: &[Uuid],
) -> std::result::Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).tasks_actions_storage_owned_ids_on_1)
        .bind(tenant.to_string())
        .bind(ids)
        .fetch_all(c)
        .await
}
pub async fn active_count_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    now: i64,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).tasks_actions_storage_active_count_on_1)
        .bind(tenant.to_string())
        .bind(device)
        .bind(now)
        .fetch_one(c)
        .await
}

pub async fn load_policy_version(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<crate::tasks::policy::CredentialPolicy> {
    crate::tasks::policy::read_in(reader, tx, id).await
}

pub async fn lock_device(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    crate::tasks::actions::agent::lock_device(profile, tx, device).await
}

pub async fn association_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> std::result::Result<Option<(String, Option<Uuid>)>, sqlx::Error> {
    sqlx::query_as(crate::storage_profile::sql(profile).tasks_actions_storage_association_on_1)
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
}
