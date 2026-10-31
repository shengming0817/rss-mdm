//! Persisted execution inputs are evidence, never a substitute for current Start admission.
use crate::{Error, Result};
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
/// Project the original task fact; current authorization belongs to the requesting business owner.
pub async fn load_in(
    store: std::sync::Arc<dyn crate::agent_facts::Store>,
    tx: &mut PgTransaction<'_>,
    run: Uuid,
    attempt: Uuid,
) -> Result<Material> {
    let tenant = tx.tenant_id().to_string();
    let payload = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(store.payload(c, tenant, run, attempt).await) })
        })
        .await??;
    Material::from_payload(&payload).ok_or_else(|| Error::Conflict.into())
}
