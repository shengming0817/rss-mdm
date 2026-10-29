//! Frozen telemetry material; historical interpretation is distinct from live admission.
/// Product-frozen authority; never accepted from the Agent upload body.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenProfile {
    pub resource_digest: [u8; 32],
    pub profile: rss_mdm_resource::TelemetryProfile,
    pub fields: Vec<rss_mdm_inventory::FieldDefinition>,
    pub collector: FrozenCollector,
    pub source: rss_mdm_inventory::Source,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Exact template contents frozen with the assignment; Resource remains the definition owner.
pub enum FrozenCollector {
    Native {
        definition: rss_mdm_resource::AgentCollectionDefinition,
    },
    Script {
        definition: rss_mdm_resource::ScriptDefinition,
        reference: String,
        length: u64,
        digest: [u8; 32],
    },
}

use crate::{Error, Failure};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
use uuid::Uuid;
/// A narrow tenant/runtime-bound publication reader, without workers or management writers.
pub struct Reader {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
}
impl Reader {
    pub fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    ) -> Self {
        Self {
            runtime,
            tenant,
            objects,
        }
    }
    /// The host binds this capability to the exact runtime used by the consuming service.
    pub fn is_bound_to(&self, runtime: &Arc<PgRuntime>, tenant: TenantId) -> bool {
        self.tenant == tenant && Arc::ptr_eq(&self.runtime, runtime)
    }
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> crate::transaction::Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    pub async fn prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &rss_mdm_policy::ExactResourceBinding,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        snapshot: &rss_mdm_authorization_service::Snapshot,
        validator: &dyn crate::inputs::ProfileValidator,
    ) -> crate::transaction::Result<FrozenProfile> {
        self.validate_in(tx)?;
        crate::management::telemetry::prepare_in(tx, binding, proof, snapshot, validator).await
    }
    /// Read on the bound consumer's already opened transaction connection.
    pub async fn current_on(
        &self,
        c: &mut sqlx::PgConnection,
        device: &str,
        policy: Uuid,
        version: Uuid,
    ) -> Result<FrozenProfile, Error> {
        current_on(
            self.tenant,
            self.objects.clone(),
            c,
            device,
            policy,
            version,
        )
        .await
    }
    /// History is read by its original identity, even after a new version or disable.
    pub async fn historical_on(
        &self,
        c: &mut sqlx::PgConnection,
        policy: Uuid,
        version: Uuid,
    ) -> Result<FrozenProfile, Error> {
        let value =
            rss_mdm_policy_postgres::telemetry::historical_on(c, self.tenant, policy, version)
                .await
                .map_err(|_| Error::Unavailable(Failure::PolicyStorage))?
                .ok_or(Error::Forbidden)?;
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::PolicyStorage))
    }
    pub async fn candidates_on(
        &self,
        c: &mut sqlx::PgConnection,
    ) -> Result<Vec<(Uuid, Uuid, serde_json::Value)>, Error> {
        rss_mdm_policy_postgres::telemetry::candidates_on(c, self.tenant)
            .await
            .map_err(|_| Error::Unavailable(Failure::PolicyStorage))
    }
    pub async fn is_current_on(
        &self,
        c: &mut sqlx::PgConnection,
        policy: Uuid,
        version: Uuid,
    ) -> Result<bool, Error> {
        rss_mdm_policy_postgres::telemetry::is_current_on(c, self.tenant, policy, version)
            .await
            .map_err(|_| Error::Unavailable(Failure::PolicyStorage))
    }
}

/// Common current-publication admission used by delivery and targeted Policy events.
pub(crate) async fn current_on(
    tenant: TenantId,
    objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    c: &mut sqlx::PgConnection,
    device: &str,
    policy: Uuid,
    version: Uuid,
) -> Result<FrozenProfile, Error> {
    let (definition, frozen) =
        rss_mdm_policy_postgres::telemetry::current_on(c, tenant, policy, version)
            .await
            .map_err(|_| Error::Unavailable(Failure::PolicyStorage))?
            .ok_or(Error::Forbidden)?;
    let admission = rss_mdm_execution_service::scope::targets::admission_on(
        objects.as_ref(),
        c,
        tenant,
        definition.scope,
        rss_mdm_inventory::Channel::Agent,
        device,
    )
    .await
    .map_err(|e| match e {
        rss_mdm_execution_service::source_authority::SourceError::Conflict => Error::Conflict,
        rss_mdm_execution_service::source_authority::SourceError::Missing => Error::Forbidden,
        _ => Error::Unavailable(Failure::PolicyStorage),
    })?;
    if !matches!(
        admission,
        rss_mdm_execution_service::source_authority::ScopeAdmission::Eligible { .. }
    ) {
        return Err(Error::Forbidden);
    }
    serde_json::from_value(frozen).map_err(|_| Error::Unavailable(Failure::PolicyStorage))
}
