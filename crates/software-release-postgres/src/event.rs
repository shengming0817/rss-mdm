use crate::db::*;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    message::*,
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgTransaction};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
/// Exact compact change event contract.
pub const EVENT_SCHEMA: &str = include_str!("../schema/changed-v1.json");
pub(crate) fn domain() -> MessagingDomain {
    MessagingDomain::parse("mdm-software-release").expect("constant domain")
}
pub(crate) async fn append(
    writer: &PgOutboxWriter,
    tx: &mut PgTransaction<'_>,
    tenant: TenantId,
    at: Timepoint,
    id: &str,
    request: &str,
    revision: u64,
) -> Result<(), PgError> {
    let payload =
        encode(&serde_json::json!({"v":1,"id":id,"request":request,"revision":revision}))?;
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tenant,
            at,
            domain(),
            data(MessageRoute::parse("software-release.changed"))?,
            ContractIdentity::new(
                data(ContractId::parse("mdm.software-release.changed"))?,
                ContractVersion::from_static_major(1),
                data(SchemaDigest::parse(&format!(
                    "sha256:{:x}",
                    Sha256::digest(EVENT_SCHEMA)
                )))?,
            ),
        ),
        MessageMetadataExtensions::new(
            None,
            Some(data(PartitionKey::parse(id))?),
            None,
            BTreeMap::new(),
        ),
    );
    // Core request identities allow characters outside the transport alphabet.
    // Keep the original in the payload/receipt; encode only the transport identity.
    let message = PendingMessage::new(MessageEnvelope::new(
        data(MessageId::parse(&format!(
            "software-release.v1:{:x}",
            Sha256::digest(request.as_bytes())
        )))?,
        metadata,
        payload,
    ));
    match writer.append(tx, message).await? {
        AppendOutcome::Inserted => Ok(()),
        AppendOutcome::AlreadyPresent => Err(fault()),
    }
}
