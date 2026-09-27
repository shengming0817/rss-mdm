use super::model::Target;
use super::state::RunState;
use crate::Error;
use crate::execution::{Result, checked_input, storage, stored};
use crate::planning::policies::admission::ExecutionPolicy;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::execution) enum Source {
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
pub(super) struct Run {
    pub id: Uuid,
    pub source: Source,
    pub target: Target,
    pub available_at: i64,
    pub deadline: i64,
    pub state: RunState,
    pub result: Option<Value>,
}
pub(super) async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
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
pub(super) async fn save_run(tx: &mut PgTransaction<'_>, run: &Run) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id.to_string();
    let state = checked_input(serde_json::to_value(&run.state))?;
    let result = run.result.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).bind(state).bind(result).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub(super) async fn replay(
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
pub(super) async fn receipt(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: Vec<u8>,
    response: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let response = response.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_receipts(tenant_id,actor,id,fingerprint,response) VALUES($1::uuid,$2,$3::uuid,$4,$5)").bind(tenant).bind(actor).bind(id.to_string()).bind(fingerprint).bind(response).execute(c).await?;Ok(())})).await?;
    Ok(())
}

pub(super) struct ScheduledPolicy {
    pub definition: ExecutionPolicy,
}
pub(super) async fn load_policy_version(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<ScheduledPolicy> {
    Ok(ScheduledPolicy {
        definition: crate::planning::policies::admission::read_in(reader, tx, id).await?,
    })
}

pub(super) async fn load_source(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    source: Source,
) -> Result<ScheduledPolicy> {
    match source {
        Source::Policy { version } => load_policy_version(reader, tx, version).await,
        Source::RemoteOperation { operation } => Ok(ScheduledPolicy {
            definition: crate::planning::policies::admission::remote_in(tx, operation).await?,
        }),
    }
}
