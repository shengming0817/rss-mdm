//! Credential publication freezes material in the initiating Policy transaction.
use super::{
    Error, Result,
    credential_tasks::FrozenCredential,
    policy::{ExecutionInput, Frozen},
};
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
pub struct Publication<'a> {
    pub operation: &'a rss_mdm_policy::CredentialOperation,
    pub architecture: rss_mdm_policy::Architecture,
    pub schedule: &'a rss_mdm_policy::schedule::Schedule,
    pub frequency: rss_mdm_policy::Frequency,
    pub lifetime: u32,
}
pub struct Inputs {
    runtime: Arc<PgRuntime>,

    enabled: bool,
}
impl Inputs {
    pub fn bind(runtime: Arc<PgRuntime>, enabled: bool) -> Self {
        Self { runtime, enabled }
    }
    pub fn publish_in(
        &self,
        tx: &PgTransaction<'_>,
        input: &Publication<'_>,
        proof: &AuthorizedPrincipal,
        snapshot: &Snapshot,
    ) -> Result<Frozen> {
        self.runtime.validate_transaction(tx)?;

        if !self.enabled {
            return Err(Error::Unsupported.into());
        }
        snapshot
            .require_all_devices(proof, super::credential_tasks::permission(input.operation))?;
        Ok(Frozen::Credential {
            frequency: input.frequency,
            action: Box::new(FrozenCredential {
                operation: input.operation.clone(),
                input: ExecutionInput {
                    platform: rss_mdm_policy::Platform::Windows,
                    architecture: input.architecture,
                    schedule: input.schedule.clone(),
                    run_lifetime_seconds: input.lifetime,
                },
            }),
        })
    }
}
