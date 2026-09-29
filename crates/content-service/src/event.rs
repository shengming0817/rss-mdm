//! Content reference facts use the existing RSS outbox in the binding transaction.
use crate::{Error, bindings::Result};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    message::*,
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::{PgOutboxWriter, PgTransaction};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
const SCHEMA: &str = include_str!("bound-v1.json");
pub fn domain() -> MessagingDomain {
    MessagingDomain::parse("mdm-content").expect("constant domain")
}
pub fn partition(tenant: TenantId, resource: &str) -> Result<PartitionIdentity> {
    Ok(PartitionIdentity::new(
        tenant,
        domain(),
        PartitionKey::parse(&format!(
            "content:{:x}",
            Sha256::digest(resource.as_bytes())
        ))
        .map_err(|_| Error::Malformed)?,
    ))
}
pub async fn append(
    writer: &PgOutboxWriter,
    tx: &mut PgTransaction<'_>,
    upload: &super::Upload,
) -> Result<()> {
    let at = Timepoint::try_from(now(tx).await?).map_err(|_| Error::Malformed)?;
    let key = PartitionKey::parse(&format!(
        "content:{:x}",
        Sha256::digest(upload.binding.resource.as_bytes())
    ))
    .map_err(|_| Error::Malformed)?;
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tx.tenant_id(),
            at,
            domain(),
            MessageRoute::parse("content.bound").map_err(|_| Error::Malformed)?,
            ContractIdentity::new(
                ContractId::parse("mdm.content.bound").map_err(|_| Error::Malformed)?,
                ContractVersion::from_static_major(1),
                SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(SCHEMA)))
                    .map_err(|_| Error::Malformed)?,
            ),
        ),
        MessageMetadataExtensions::new(None, Some(key), None, BTreeMap::new()),
    );
    let payload=serde_json::to_vec(&serde_json::json!({"v":1,"operation":upload.id,"resource":upload.binding.resource,"version":upload.binding.version,"reference":upload.binding.reference,"length":upload.binding.length,"sha256":upload.binding.sha256})).map_err(|_|Error::Malformed)?;
    let message = PendingMessage::new(MessageEnvelope::new(
        MessageId::parse(&format!(
            "content.v1:{:x}:{}",
            Sha256::digest(upload.binding.actor.as_bytes()),
            upload.id
        ))
        .map_err(|_| Error::Malformed)?,
        metadata,
        payload,
    ));
    match writer
        .append(tx, message)
        .await
        .map_err(rss_transactional_messaging_postgres::PgError::from)?
    {
        AppendOutcome::Inserted => Ok(()),
        AppendOutcome::AlreadyPresent => Err(Error::Conflict.into()),
    }
}

async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}
