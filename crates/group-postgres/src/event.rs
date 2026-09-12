use crate::{Receipt, storage::*};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use rss_transactional_messaging_postgres::PgError;
use serde::Serialize;
use std::collections::BTreeMap;

/// Exact v1 event JSON schema; its byte digest is carried in RSS message metadata.
pub const EVENT_SCHEMA: &str = include_str!("../schema/group-changed-v1.json");
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChangeKind {
    Created,
    Edited,
    RuleChanged,
    MembersChanged,
    Deleted,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Event<'a> {
    v: u8,
    kind: ChangeKind,
    group_id: String,
    operation_id: String,
    group_revision: i64,
    member_version: i64,
    member_count: usize,
    added: usize,
    removed: usize,
    rule_version: &'a Option<String>,
}
pub(crate) fn domain() -> MessagingDomain {
    MessagingDomain::parse("mdm-group").expect("constant domain")
}
pub(crate) fn message(
    tenant: TenantId,
    at: Timepoint,
    kind: ChangeKind,
    r: &Receipt,
) -> Result<PendingMessage<Vec<u8>>, PgError> {
    let payload = data(crate::codec::encode(&Event {
        v: 1,
        kind,
        group_id: r.group.id.to_string(),
        operation_id: r.operation.to_string(),
        group_revision: r.group.revision.get(),
        member_version: r.group.member_version,
        member_count: r.group.member_count,
        added: r.added,
        removed: r.removed,
        rule_version: &r.group.rule_version,
    }))?;
    let schema = format!("sha256:{:x}", sha2::Sha256::digest(EVENT_SCHEMA.as_bytes()));
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tenant,
            at,
            domain(),
            data(MessageRoute::parse("group.changed"))?,
            ContractIdentity::new(
                data(ContractId::parse("mdm.group.changed"))?,
                ContractVersion::from_static_major(1),
                data(SchemaDigest::parse(&schema))?,
            ),
        ),
        MessageMetadataExtensions::new(
            None,
            Some(data(PartitionKey::parse(&r.group.id.to_string()))?),
            None,
            BTreeMap::new(),
        ),
    );
    Ok(PendingMessage::new(MessageEnvelope::new(
        data(MessageId::parse(&format!(
            "group.changed.v1:{}",
            r.operation
        )))?,
        metadata,
        payload,
    )))
}
use sha2::Digest;
