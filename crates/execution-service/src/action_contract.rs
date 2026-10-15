//! Frozen execution contract. It deliberately excludes authors, approval rows and Scope internals.
use crate::Error;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::schedule::Schedule;
pub use rss_mdm_policy::{Architecture, Platform};
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenAction {
    pub input: ExecutionInput,
    pub parameters: rss_mdm_policy::ParameterSources,
    pub resource: wire::TaskResource,
    pub definition: r::ScriptDefinition,
    pub collection: Option<rss_mdm_inventory::CollectionDefinition>,
    pub resource_digest: [u8; 32],
    pub artifact_reference: String,
    pub content: wire::TaskContent,
}
impl FrozenAction {
    pub fn artifact(&self) -> Result<r::Artifact, Error> {
        r::Artifact::new(
            r::Id::new(&self.artifact_reference).map_err(|_| Error::Malformed)?,
            self.content.length,
            r::Digest::from_bytes(self.content.sha256),
        )
        .map_err(|_| Error::Malformed)
    }
}
/// Enterprise software input frozen at Policy publication, before per-device admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenSoftwareAction {
    pub delivery: rss_mdm_policy::SoftwareDelivery,
    pub resource: String,
    pub version: String,
    pub variants: BTreeMap<rss_mdm_policy::SoftwareTarget, String>,
    pub resource_digest: [u8; 32],
    pub admission_operation: uuid::Uuid,
    pub intent: rss_mdm_policy::SoftwareIntent,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenNativeCollection {
    pub input: ExecutionInput,
    pub definition: r::NativeCollectionDefinition,
    pub windows_plan: Option<rss_mdm_windows_mdm::native::collection::Plan>,
    pub grants: BTreeMap<String, Vec<crate::authorization::UserGrant>>,
    pub collection: rss_mdm_inventory::CollectionDefinition,
    pub resource_digest: [u8; 32],
}
pub trait ScheduledInput {
    fn execution_input(&self) -> &ExecutionInput;
}
impl ScheduledInput for FrozenAction {
    fn execution_input(&self) -> &ExecutionInput {
        &self.input
    }
}
impl ScheduledInput for FrozenNativeCollection {
    fn execution_input(&self) -> &ExecutionInput {
        &self.input
    }
}

impl FrozenNativeCollection {
    pub fn permissions(&self) -> Result<Vec<crate::authorization::Permission>, Error> {
        let mut permissions = vec![crate::authorization::Permission::InventoryCollect];
        if let Some(plan) = &self.windows_plan {
            for request in plan.requests().map_err(|_| Error::Malformed)? {
                permissions.extend(
                    crate::Task::Windows {
                        request: rss_mdm_windows_mdm::native::Execution::SyncMl { request },
                    }
                    .permissions()?,
                );
            }
        }
        // Collection facts flow to Inventory; credential-bearing carriers are not asset fields.
        if permissions.contains(&crate::authorization::Permission::Credentials) {
            return Err(Error::Unsupported);
        }
        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }
}

/// Frozen native Agent input, independent of script permissions and profiles.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenAgentCollection {
    pub grants: BTreeMap<String, Vec<crate::authorization::UserGrant>>,
    pub input: ExecutionInput,
    pub resource: wire::TaskResource,
    pub definition: r::AgentCollectionDefinition,
    pub collection: rss_mdm_inventory::CollectionDefinition,
    pub resource_digest: [u8; 32],
}
impl ScheduledInput for FrozenAgentCollection {
    fn execution_input(&self) -> &ExecutionInput {
        &self.input
    }
}

impl FrozenAgentCollection {
    pub fn permissions(&self) -> Vec<crate::authorization::Permission> {
        use crate::authorization::Permission as P;
        // Full query evidence includes unmapped properties and queries; mapped field
        // sensitivity cannot authorize collecting or disclosing that wider result.
        vec![P::InventoryCollect, P::InventorySensitiveRead]
    }
    pub async fn authorized_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        target: &crate::Target,
        now: i64,
    ) -> crate::transaction::Result<bool> {
        let Some(grants) = self
            .grants
            .get(&target.device)
            .or_else(|| self.grants.get("*"))
        else {
            return Ok(false);
        };
        let tenant = tx.tenant_id().to_string();
        let registration = target.registration;
        let enabled:bool=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='agent.native' AND enabled)").bind(tenant).bind(registration).fetch_one(c).await})).await?;
        if !enabled {
            return Ok(false);
        }
        let grants = grants.clone();
        let permissions = self.permissions();
        tx.with_connection(move |c| {
            Box::pin(async move {
                for permission in permissions {
                    let mut allowed = false;
                    for grant in &grants {
                        if grant.valid(c, permission, now).await.map_err(|_| {
                            sqlx::Error::Protocol("native collection authority".into())
                        })? {
                            allowed = true;
                            break;
                        }
                    }
                    if !allowed {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
        })
        .await
        .map_err(Into::into)
    }
}
