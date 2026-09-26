use super::*;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_transactional_messaging::message::*;
use rss_transactional_messaging::outbox::{AppendOutcome, OutboxWriter, PendingMessage};
use std::collections::BTreeMap;
const SCHEMA: &str = include_str!("changed-v1.json");
pub(super) fn domain() -> MessagingDomain {
    MessagingDomain::parse("mdm-software").expect("constant domain")
}
pub(super) fn partition(tenant: TenantId, key: &str) -> Result<PartitionIdentity> {
    Ok(PartitionIdentity::new(
        tenant,
        domain(),
        PartitionKey::parse(&format!("software:{:x}", Sha256::digest(key.as_bytes())))
            .map_err(|_| Error::Input)?,
    ))
}
pub(super) async fn append(
    writer: &PgOutboxWriter,
    tx: &mut PgTransaction<'_>,
    key: &str,
    id: uuid::Uuid,
    value: &Value,
) -> Result<()> {
    let at = Timepoint::try_from(storage::now(tx).await?).map_err(|_| Error::Integrity)?;
    let payload = serde_json::to_vec(&json!({"v":1,"key":key,"operation":id,"state":value}))
        .map_err(|_| Error::Input)?;
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tx.tenant_id(),
            at,
            domain(),
            MessageRoute::parse("software.changed").map_err(|_| Error::Input)?,
            ContractIdentity::new(
                ContractId::parse("mdm.software.changed").map_err(|_| Error::Input)?,
                ContractVersion::from_static_major(1),
                SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(SCHEMA)))
                    .map_err(|_| Error::Input)?,
            ),
        ),
        MessageMetadataExtensions::new(
            None,
            Some(
                PartitionKey::parse(&format!("software:{:x}", Sha256::digest(key.as_bytes())))
                    .map_err(|_| Error::Input)?,
            ),
            None,
            BTreeMap::new(),
        ),
    );
    let message = PendingMessage::new(MessageEnvelope::new(
        MessageId::parse(&format!("software.v1:{id}")).map_err(|_| Error::Input)?,
        metadata,
        payload,
    ));
    match writer.append(tx, message).await.map_err(PgError::from)? {
        AppendOutcome::Inserted => Ok(()),
        AppendOutcome::AlreadyPresent => Err(Error::Integrity),
    }
}
