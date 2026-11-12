//! Fixed fact-to-owner scheduling. Business cursors and decisions remain in each owner.
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
    PgConsumerEffect, PgConsumerEffectFailure, PgTransaction,
};
use sha2::{Digest, Sha256};

pub(crate) const DOMAIN: &str = "mdm-assets";
pub(crate) const CONSUMER: &str = "mdm-asset-inputs";
pub(crate) struct Validator {
    pub tenant: TenantId,
}
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        let message = challenge.message();
        let contract = message.metadata().contract();
        if message.metadata().tenant_id() != self.tenant || message.payload().len() > 131_072 {
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
        if tenant.as_bytes() != &self.tenant.octets() || message.id().as_str() != identity {
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
        Ok(challenge.verified())
    }
}
pub(crate) struct Receiver {
    pub messaging: rss_reconcile_postgres::PgMessagingStore,
}
impl PgConsumerEffect<Vec<u8>> for Receiver {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        // Keep this lock order fixed. No owner progress or business tables are accessed here.
        rss_mdm_group_service::input_wake::wake_in(&self.messaging, tx)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        if message.metadata().route().as_str() == "asset.changed" {
            rss_mdm_compliance_service::input_wake::wake_in(&self.messaging, tx)
                .await
                .map_err(PgConsumerEffectFailure::infrastructure)?;
        }
        rss_mdm_scope_service::tasks::wake_inputs_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &self.messaging,
            tx,
        )
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        rss_mdm_policy_service::configuration::wake::inputs_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &self.messaging,
            tx,
        )
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Succeeded)
    }
}
