//! Immutable access publication participates in the Policy owner's transaction.
use super::execution::{Error, Result};
use rss_mdm_agent_wire::runtime::AccessConfiguration;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frozen {
    DeviceAccess { configuration: AccessConfiguration },
}
pub struct Inputs {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    signing_enabled: bool,
}
impl Inputs {
    pub fn bind(runtime: Arc<PgRuntime>, tenant: TenantId, signing_enabled: bool) -> Self {
        Self {
            runtime,
            tenant,
            signing_enabled,
        }
    }
    pub fn publish_in(
        &self,
        tx: &PgTransaction<'_>,
        configuration: AccessConfiguration,
        proof: &AuthorizedPrincipal,
        snapshot: &Snapshot,
    ) -> Result<Frozen> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        if !self.signing_enabled {
            return Err(Error::Unsupported.into());
        }
        snapshot.require_all_devices(proof, Permission::AccountWrite)?;
        configuration.validate().map_err(|_| Error::Malformed)?;
        Ok(Frozen::DeviceAccess { configuration })
    }
}
