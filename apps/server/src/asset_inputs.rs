//! Fixed fact-to-owner scheduling. Business cursors and decisions remain in each owner.
use rss_transactional_messaging::{
    message::MessageEnvelope,
    policy::OperationDeadline,
    transaction::{
        EnvelopeValidationFailure, IngressChallenge, IngressValidator, TerminalDisposition,
        VerifiedIngress,
    },
};
use rss_transactional_messaging_postgres::{
    PgConsumerEffect, PgConsumerEffectFailure, PgTransaction,
};
use sha2::{Digest, Sha256};

pub(crate) const DOMAIN: &str = "mdm-assets";
pub(crate) const CONSUMER: &str = "mdm-asset-inputs";
pub(crate) struct Validator {
    pub storage: rss_transactional_messaging::fence::StorageIdentity,
}
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        let message = challenge.message();
        let contract = message.metadata().contract();
        let payload_limit = if message.metadata().route().as_str() == "asset.changed" {
            1024 * 1024
        } else {
            131_072
        };
        if message.payload().len() > payload_limit {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        let (schema, expected_contract, tenant, identity) =
            match message.metadata().route().as_str() {
                "asset.changed" => {
                    let event: rss_mdm_inventory::AssetChanged =
                        serde_json::from_slice(message.payload())
                            .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
                    event
                        .validate()
                        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
                    (
                        rss_mdm_inventory::ASSET_CHANGED_SCHEMA,
                        "mdm.asset.changed",
                        event.tenant,
                        event.message_id(),
                    )
                }
                "object.published" => {
                    let event: rss_mdm_device_service::object_published::ObjectPublished =
                        serde_json::from_slice(message.payload())
                            .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
                    if !event.valid() {
                        return Err(EnvelopeValidationFailure::MalformedMetadata);
                    }
                    (
                        rss_mdm_device_service::object_published::SCHEMA,
                        "mdm.device.object-published",
                        event.tenant,
                        event.message_id(),
                    )
                }
                _ => return Err(EnvelopeValidationFailure::UnsupportedContract),
            };
        if tenant.as_bytes() != &message.metadata().tenant_id().octets()
            || message.id().as_str() != identity
        {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        if message.metadata().domain().as_str() != DOMAIN
            || contract.id().as_str() != expected_contract
            || contract.version() != rss_contract::ContractVersion::from_static_major(1)
            || contract.schema_digest().as_str()
                != format!("sha256:{:x}", Sha256::digest(schema.as_bytes()))
        {
            return Err(EnvelopeValidationFailure::UnsupportedContract);
        }
        let execution = execution(message, self.storage)?;
        Ok(challenge.verified(execution))
    }
}
pub(crate) struct Receiver {
    pub storage: rss_transactional_messaging::fence::StorageIdentity,
    pub messaging: rss_reconcile_postgres::PgMessagingStore,
}
impl PgConsumerEffect<Vec<u8>> for Receiver {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let binding = execution(message, self.storage).map_err(|e| {
            PgConsumerEffectFailure::handler_transient(sqlx::Error::Protocol(format!(
                "asset execution: {e:?}"
            )))
        })?;
        // Keep this lock order fixed. No owner progress or business tables are accessed here.
        rss_mdm_group_service::input_wake::wake_in(&self.messaging, tx, binding)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        if message.metadata().route().as_str() == "asset.changed" {
            rss_mdm_device_service::worker::wake_inputs_in(&self.messaging, tx, binding)
                .await
                .map_err(PgConsumerEffectFailure::infrastructure)?;
            rss_mdm_compliance_postgres::wake_inputs_in(&self.messaging, tx, binding)
                .await
                .map_err(PgConsumerEffectFailure::infrastructure)?;
        }
        rss_mdm_scope_service::tasks::wake_inputs_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &self.messaging,
            tx,
            binding,
        )
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        rss_mdm_policy_service::configuration::wake::inputs_in(
            binding,
            rss_mdm_install_support::StorageProfile::Mdm,
            &self.messaging,
            tx,
        )
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        rss_mdm_device_service::control::source_changes::wake_in(binding, &self.messaging, tx)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        rss_mdm_software_service::deployment::source_changes::wake_in(binding, &self.messaging, tx)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Succeeded)
    }
}

fn execution(
    message: &MessageEnvelope<Vec<u8>>,
    storage: rss_transactional_messaging::fence::StorageIdentity,
) -> Result<rss_transactional_messaging::fence::ExecutionBinding, EnvelopeValidationFailure> {
    let document: serde_json::Value = serde_json::from_slice(message.payload())
        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
    let epoch = document
        .get("executionEpoch")
        .and_then(serde_json::Value::as_i64)
        .ok_or(EnvelopeValidationFailure::MalformedMetadata)?;
    let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
        .map_err(|_| EnvelopeValidationFailure::MalformedMetadata)?;
    Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
        storage,
        message.metadata().tenant_id(),
        epoch,
    ))
}
