//! Persisted execution inputs are evidence, never a substitute for current Start admission.
use crate::{Error, Result, stored, transaction::*};
use rss_mdm_agent_wire::runtime as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Material {
    DeviceAccess {
        task: Box<wire::AccessTaskSpec>,
    },
    Credential {
        task: Box<wire::CredentialTaskSpec>,
    },
    Collection {
        plan: wire::NativeCollectionPlan,
        resource_digest: [u8; 32],
    },
    Script {
        target: wire::SoftwareExecutionTarget,
    },
    Software {
        platform: wire::TaskPlatform,
        intent: wire::SoftwareTaskIntent,
        definition_digest: [u8; 32],
        steps: Vec<wire::SoftwareTaskStep>,
    },
}
impl Material {
    pub fn from_payload(payload: &wire::TaskPayload) -> Option<Self> {
        match payload {
            wire::TaskPayload::DeviceAccess(spec) => {
                Some(Self::DeviceAccess { task: spec.clone() })
            }
            wire::TaskPayload::Credential(spec) => Some(Self::Credential { task: spec.clone() }),
            wire::TaskPayload::Collection(spec) => Some(Self::Collection {
                plan: spec.plan.clone(),
                resource_digest: spec.resource_digest,
            }),
            wire::TaskPayload::Script(spec) => Some(Self::Script {
                target: spec.execution_target.clone(),
            }),
            wire::TaskPayload::Software(spec) => Some(Self::Software {
                platform: spec.platform,
                intent: spec.intent,
                definition_digest: spec.definition_digest,
                steps: spec.steps.clone(),
            }),
            _ => None,
        }
    }
}
pub async fn persist_in(
    tx: &mut PgTransaction<'_>,
    run: Uuid,
    attempt: Uuid,
    payload: &wire::TaskPayload,
) -> Result<()> {
    let Some(material) = Material::from_payload(payload) else {
        return Ok(());
    };
    let tenant = tx.tenant_id().to_string();
    let material = json(&material)?;
    let changed = tx.with_connection(move |c| Box::pin(async move {
        Ok(sqlx::query("UPDATE mdm_commands.action_attempts SET execution_material=$4 WHERE tenant_id=$1::uuid AND run=$2 AND id=$3").bind(tenant).bind(run).bind(attempt).bind(material).execute(c).await?.rows_affected())
    })).await?;
    if changed != 1 {
        return Err(Error::Conflict.into());
    }
    Ok(())
}
pub async fn load_in(tx: &mut PgTransaction<'_>, run: Uuid, attempt: Uuid) -> Result<Material> {
    let tenant = tx.tenant_id().to_string();
    let material: Option<serde_json::Value> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT execution_material FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND run=$2 AND id=$3").bind(tenant).bind(run).bind(attempt).fetch_one(c).await
    })).await?;
    stored(serde_json::from_value(material.ok_or(Error::Conflict)?))
}
