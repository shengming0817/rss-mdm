use crate::{Receipt, storage::*};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use rss_transactional_messaging_postgres::PgError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Exact v1 event JSON schema; its byte digest is carried in RSS message metadata.
pub const EVENT_SCHEMA: &str = include_str!("../schema/group-changed-v1.json");
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Closed Group change facts consumed by independent product owners.
pub enum GroupChangeKind {
    /// Created fact.
    Created,
    /// Edited fact.
    Edited,
    /// RuleChanged fact.
    RuleChanged,
    /// MembersChanged fact.
    MembersChanged,
    /// AuthorityChanged fact.
    AuthorityChanged,
    /// Deleted fact.
    Deleted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current V1 Group event, atomically committed with the originating operation.
pub struct GroupChanged {
    /// Frozen v of the originating Group operation.
    pub v: u8,
    /// Frozen kind of the originating Group operation.
    pub kind: GroupChangeKind,
    /// Frozen group id of the originating Group operation.
    pub group_id: String,
    /// Frozen operation id of the originating Group operation.
    pub operation_id: String,
    /// Frozen group revision of the originating Group operation.
    pub group_revision: i64,
    /// Frozen member version of the originating Group operation.
    pub member_version: i64,
    /// Frozen authority version of the originating Group operation.
    pub authority_version: u64,
    /// Frozen member count of the originating Group operation.
    pub member_count: usize,
    /// Frozen added of the originating Group operation.
    pub added: usize,
    /// Frozen removed of the originating Group operation.
    pub removed: usize,
    /// Frozen rule version of the originating Group operation.
    pub rule_version: Option<String>,
}
pub(crate) fn domain() -> MessagingDomain {
    MessagingDomain::parse("mdm-group").expect("constant domain")
}
pub(crate) fn message(
    tenant: TenantId,
    at: Timepoint,
    kind: GroupChangeKind,
    r: &Receipt,
    authority_version: u64,
) -> Result<PendingMessage<Vec<u8>>, PgError> {
    let payload = data(crate::codec::encode(&GroupChanged {
        v: 1,
        kind,
        group_id: r.group.id.to_string(),
        operation_id: r.operation.to_string(),
        group_revision: r.group.revision.get(),
        member_version: r.group.member_version,
        authority_version,
        member_count: r.group.member_count,
        added: r.added,
        removed: r.removed,
        rule_version: r.group.rule_version.clone(),
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
