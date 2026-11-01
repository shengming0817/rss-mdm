//! Credential publication freezes material in the initiating Policy transaction.
use super::{
    Error, Result,
    credential_tasks::FrozenCredential,
    policy::{ExecutionInput, Frozen},
};
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
pub struct Inputs {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    enabled: bool,
}
impl Inputs {
    pub fn bind(runtime: Arc<PgRuntime>, tenant: TenantId, enabled: bool) -> Self {
        Self {
            runtime,
            tenant,
            enabled,
        }
    }
    pub fn publish_in(
        &self,
        tx: &PgTransaction<'_>,
        definition: &rss_mdm_policy::Action,
        proof: &AuthorizedPrincipal,
        snapshot: &Snapshot,
    ) -> Result<Frozen> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        if !self.enabled {
            return Err(Error::Unsupported.into());
        }
        let rss_mdm_policy::Action::Credential {
            operation,
            architecture,
            schedule,
            frequency,
            run_lifetime_seconds,
        } = definition
        else {
            return Err(Error::Unsupported.into());
        };
        snapshot.require_all_devices(proof, super::credential_tasks::permission(operation))?;
        Ok(Frozen::Credential {
            frequency: *frequency,
            action: Box::new(FrozenCredential {
                operation: operation.clone(),
                input: ExecutionInput {
                    platform: rss_mdm_policy::Platform::Windows,
                    architecture: *architecture,
                    schedule: schedule.clone(),
                    run_lifetime_seconds: *run_lifetime_seconds,
                },
            }),
        })
    }
}
