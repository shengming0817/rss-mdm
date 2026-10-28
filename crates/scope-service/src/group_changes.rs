//! Scope is the sole local consumer of the Group event stream.
use rss_mdm_group_postgres::{GroupChangeKind, GroupChanged};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    message::MessageEnvelope,
    policy::OperationDeadline,
    transaction::{
        EnvelopeValidationFailure, IngressChallenge, IngressValidator, TerminalDisposition,
        VerifiedIngress,
    },
};
use rss_transactional_messaging_postgres::{
    PgConsumerEffect, PgConsumerEffectFailure, PgRuntime, PgTransaction,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const DOMAIN: &str = "mdm-group";
pub const CONSUMER: &str = "mdm-scope-group-changes";
pub struct Validator {
    pub tenant: TenantId,
}
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        let message = challenge.message();
        let contract = message.metadata().contract();
        if message.metadata().tenant_id() != self.tenant {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        let digest = format!(
            "sha256:{:x}",
            Sha256::digest(rss_mdm_group_postgres::EVENT_SCHEMA.as_bytes())
        );
        if contract.id().as_str() != "mdm.group.changed"
            || contract.version() != rss_contract::ContractVersion::from_static_major(1)
            || contract.schema_digest().as_str() != digest
            || message.metadata().domain().as_str() != DOMAIN
            || message.metadata().route().as_str() != "group.changed"
        {
            return Err(EnvelopeValidationFailure::UnsupportedContract);
        }
        let event: GroupChanged = serde_json::from_slice(message.payload())
            .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
        let operation = rss_mdm_group::OperationId::parse(&event.operation_id)
            .map_err(|_| EnvelopeValidationFailure::MalformedIdentity)?;
        rss_mdm_group::GroupId::parse(&event.group_id)
            .map_err(|_| EnvelopeValidationFailure::MalformedIdentity)?;
        if event.v != 1
            || event.group_revision < 1
            || event.member_version < 0
            || event.authority_version > i64::MAX as u64
            || event.member_count > 1_000_000
            || event.added > 1_000_000
            || event.removed > 1_000_000
            || message.id().as_str() != format!("group.changed.v1:{operation}")
            || event.rule_version.as_ref().is_some_and(|s| s.len() > 256)
        {
            return Err(EnvelopeValidationFailure::MalformedMetadata);
        }
        Ok(challenge.verified())
    }
}
pub struct Receiver {
    binding: rss_mdm_scope_postgres::ScopeBinding,
}
impl Receiver {
    pub fn new(runtime: Arc<PgRuntime>, tenant: TenantId) -> Self {
        Self {
            binding: rss_mdm_scope_postgres::ScopeBinding::new(runtime, tenant),
        }
    }
}
impl PgConsumerEffect<Vec<u8>> for Receiver {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let event: GroupChanged = serde_json::from_slice(message.payload())
            .map_err(PgConsumerEffectFailure::handler_transient)?;
        // Presentation changes do not change Scope membership or authorization.
        if !matches!(event.kind, GroupChangeKind::Edited) {
            let group = uuid::Uuid::parse_str(&event.group_id)
                .map_err(PgConsumerEffectFailure::handler_transient)?;
            self.binding
                .accept_group_change_in(tx, message.id().as_str(), group)
                .await
                .map_err(|e| match e {
                    rss_mdm_scope_postgres::BindingError::Storage(e) => {
                        PgConsumerEffectFailure::infrastructure(e)
                    }
                    e => PgConsumerEffectFailure::handler_transient(e),
                })?;
        }
        Ok(TerminalDisposition::Succeeded)
    }
}
