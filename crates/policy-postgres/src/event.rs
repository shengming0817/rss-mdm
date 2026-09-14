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
    MessagingDomain::parse("mdm-policy").expect("constant domain")
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
            data("event::append", MessageRoute::parse("policy.changed"))?,
            ContractIdentity::new(
                data("event::append", ContractId::parse("mdm.policy.changed"))?,
                ContractVersion::from_static_major(1),
                data(
                    "event::append",
                    SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(EVENT_SCHEMA))),
                )?,
            ),
        ),
        MessageMetadataExtensions::new(
            None,
            Some(data("event::append", PartitionKey::parse(id))?),
            None,
            BTreeMap::new(),
        ),
    );
    let message = PendingMessage::new(MessageEnvelope::new(
        data(
            "event::append",
            MessageId::parse(&format!("policy.v1:{request}")),
        )?,
        metadata,
        payload,
    ));
    match writer.append(tx, message).await? {
        AppendOutcome::Inserted => Ok(()),
        AppendOutcome::AlreadyPresent => Err(fault("event::append")),
    }
}
