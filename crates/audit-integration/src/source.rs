//! Frozen MDM facts. Source time is durable before projection; sink time is never authored here.
use crate::{Error, Fact};
use rss_audit_core::*;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::{RequestId, TenantId};
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_SOURCE_BYTES: usize = 262_144;
pub(crate) const DOMAIN: &str = "mdm.audit";
pub(crate) const GROUP: &str = "mdm.audit.v1";
const WIRE_SCHEMA: &[u8] = b"mdm.audit.source.v1:version,tenant,source,event,contract,contract_version,schema_digest,fingerprint,actor_kind,actor,action,resource_kind,resource,outcome,occurred_at,correlation,request,operation,payload";
use sha2::{Digest, Sha256};

/// The current product source protocol, separate from the final Audit record encoding.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEvent {
    version: u8,
    tenant: String,
    source: String,
    event: String,
    contract: String,
    contract_version: u32,
    schema_digest: String,
    fingerprint: [u8; 32],
    actor_kind: String,
    actor: String,
    action: String,
    resource_kind: String,
    resource: String,
    outcome: SourceOutcome,
    occurred_at: i64,
    correlation: Option<String>,
    request: Option<String>,
    operation: Option<String>,
    // A string preserves every UTF-8 payload byte, including whitespace and key order.
    payload: String,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceOutcome {
    Succeeded,
    Denied,
    Failed,
    Unknown,
}
impl From<Outcome> for SourceOutcome {
    fn from(value: Outcome) -> Self {
        match value {
            Outcome::Succeeded => Self::Succeeded,
            Outcome::Denied => Self::Denied,
            Outcome::Failed => Self::Failed,
            Outcome::Unknown => Self::Unknown,
        }
    }
}
impl From<SourceOutcome> for Outcome {
    fn from(value: SourceOutcome) -> Self {
        match value {
            SourceOutcome::Succeeded => Self::Succeeded,
            SourceOutcome::Denied => Self::Denied,
            SourceOutcome::Failed => Self::Failed,
            SourceOutcome::Unknown => Self::Unknown,
        }
    }
}
pub(crate) struct FrozenFact {
    source: SourceEvent,
    bytes: Vec<u8>,
}
impl FrozenFact {
    pub(crate) fn freeze(fact: &Fact, occurred_at: Timepoint) -> Result<Self, Error> {
        let event = fact.event(occurred_at)?;
        let id = event.identity();
        let source = id.source();
        let facts = event.facts();
        let coordinates = event.context().coordinates();
        let source = SourceEvent {
            version: 1,
            tenant: id.tenant().to_string(),
            source: source.source_id().as_str().into(),
            event: id.event_id().as_str().into(),
            contract: source.contract().id().as_str().into(),
            contract_version: source.contract().version().major(),
            schema_digest: source.contract().schema_digest().as_str().into(),
            fingerprint: *fact.fingerprint(),
            actor_kind: facts.actor().kind().as_str().into(),
            actor: facts.actor().id().as_str().into(),
            action: facts.action().as_str().into(),
            resource_kind: facts.resource().kind().as_str().into(),
            resource: facts.resource().id().as_str().into(),
            outcome: facts.outcome().into(),
            occurred_at: occurred_at.unix_seconds(),
            correlation: coordinates
                .correlation_id()
                .map(|value| value.as_str().to_owned()),
            request: coordinates.request_id().map(ToString::to_string),
            operation: coordinates
                .operation_id()
                .map(|value| value.as_str().to_owned()),
            payload: checked(String::from_utf8(
                event.context().payload().as_bytes().to_vec(),
            ))?,
        };
        let bytes = checked(serde_json::to_vec(&source))?;
        Self::decode(&bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
            return Err(Error::Receipt);
        }
        let source: SourceEvent = checked(serde_json::from_slice(bytes))?;
        if source.version != 1
            || source.contract != "mdm.audit.fact"
            || source.contract_version != 1
            || source.schema_digest
                != format!("sha256:{:x}", Sha256::digest(crate::fact::SOURCE_SCHEMA))
            || !matches!(source.source.as_str(), "mdm.business" | "mdm.request")
            || checked(serde_json::to_vec(&source))? != bytes
        {
            return Err(Error::Receipt);
        }
        let frozen = Self {
            source,
            bytes: bytes.to_vec(),
        };
        // Validate the complete Audit contract now, without assigning the eventual sink time.
        frozen.prepare(frozen.occurred_at()?)?;
        Ok(frozen)
    }
    pub(crate) fn domain() -> Result<MessagingDomain, Error> {
        checked(MessagingDomain::parse(DOMAIN))
    }
    pub(crate) fn contract() -> Result<ContractIdentity, Error> {
        Ok(ContractIdentity::new(
            checked(ContractId::parse("mdm.audit.source"))?,
            checked(ContractVersion::from_major(1))?,
            checked(SchemaDigest::parse(&format!(
                "sha256:{:x}",
                Sha256::digest(WIRE_SCHEMA)
            )))?,
        ))
    }
    pub(crate) fn partition(&self) -> Result<PartitionIdentity, Error> {
        let kind = if self.source.source == "mdm.request" {
            format!("request:{}", self.source.resource_kind)
        } else {
            self.source.resource_kind.clone()
        };
        partition(self.identity()?.tenant(), &kind, &self.source.resource)
    }
    pub(crate) fn message(&self) -> Result<PendingMessage<Vec<u8>>, Error> {
        let identity = self.identity()?;
        let encoded = checked(serde_json::to_vec(&(
            &self.source.tenant,
            &self.source.source,
            &self.source.event,
        )))?;
        let id = checked(MessageId::parse(&format!(
            "mdm-audit-{:x}",
            Sha256::digest(encoded)
        )))?;
        let metadata = MessageMetadata::new(
            AuthoredMessageMetadata::new(
                identity.tenant(),
                self.occurred_at()?,
                Self::domain()?,
                checked(MessageRoute::parse("fact.project"))?,
                Self::contract()?,
            ),
            MessageMetadataExtensions::new(
                checked(
                    self.source
                        .correlation
                        .as_deref()
                        .map(CorrelationId::parse)
                        .transpose(),
                )?,
                Some(self.partition()?.key().clone()),
                None,
                Default::default(),
            ),
        );
        Ok(PendingMessage::new(MessageEnvelope::new(
            id,
            metadata,
            self.bytes.clone(),
        )))
    }
    pub(crate) fn reserve_eligible(&self) -> bool {
        matches!(
            self.source.outcome,
            SourceOutcome::Denied | SourceOutcome::Failed
        ) || (self.source.outcome == SourceOutcome::Unknown
            && serde_json::from_str::<serde_json::Value>(&self.source.payload)
                .ok()
                .and_then(|payload| payload["status"].as_u64())
                .is_some_and(|status| status >= 400))
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn fingerprint(&self) -> &[u8; 32] {
        &self.source.fingerprint
    }
    pub(crate) fn occurred_at(&self) -> Result<Timepoint, Error> {
        checked(Timepoint::try_from(self.source.occurred_at))
    }
    pub(crate) fn identity(&self) -> Result<RecordIdentity, Error> {
        Ok(RecordIdentity::new(
            checked(TenantId::parse(&self.source.tenant))?,
            SourceIdentity::new(
                checked(SourceId::parse(&self.source.source))?,
                SourceContract::new(
                    checked(ContractId::parse(&self.source.contract))?,
                    checked(ContractVersion::from_major(self.source.contract_version))?,
                    checked(SchemaDigest::parse(&self.source.schema_digest))?,
                ),
            ),
            checked(EventId::parse(&self.source.event))?,
        ))
    }
    pub(crate) fn event(&self) -> Result<AuditEventV1, Error> {
        let s = &self.source;
        Ok(AuditEventV1::new(
            self.identity()?,
            EventFacts::new(
                ActorRef::new(
                    checked(ActorKind::parse(&s.actor_kind))?,
                    checked(ActorId::parse(&s.actor))?,
                ),
                checked(Action::parse(&s.action))?,
                ResourceRef::new(
                    checked(ResourceKind::parse(&s.resource_kind))?,
                    checked(ResourceId::parse(&s.resource))?,
                ),
                s.outcome.into(),
                self.occurred_at()?,
            ),
            EventContext::new(
                Coordinates::new(
                    checked(
                        s.correlation
                            .as_deref()
                            .map(CorrelationId::parse)
                            .transpose(),
                    )?,
                    checked(s.request.as_deref().map(RequestId::parse).transpose())?,
                    checked(s.operation.as_deref().map(OperationId::parse).transpose())?,
                ),
                checked(AuditPayload::new(s.payload.as_bytes().to_vec()))?,
            ),
        ))
    }
    pub(crate) fn prepare(&self, recorded_at: Timepoint) -> Result<PreparedAuditV1, Error> {
        rss_audit_core::prepare(self.event()?, recorded_at)
            .map_err(|error| Error::Audit(error.into()))
    }
    pub(crate) fn same_facts(&self, candidate: &Self) -> bool {
        let mut candidate = candidate.source.clone();
        candidate.occurred_at = self.source.occurred_at;
        self.source == candidate
    }
}
fn checked<T, E>(value: Result<T, E>) -> Result<T, Error> {
    value.map_err(|_| Error::Receipt)
}

pub(crate) fn partition(
    tenant: TenantId,
    kind: &str,
    resource: &str,
) -> Result<PartitionIdentity, Error> {
    let identity = checked(serde_json::to_vec(&(kind, resource)))?;
    let key = checked(PartitionKey::parse(&format!(
        "object-{:x}",
        Sha256::digest(identity)
    )))?;
    Ok(PartitionIdentity::new(tenant, FrozenFact::domain()?, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestAudit;
    fn context() -> RequestAudit {
        let audit = RequestAudit::new(
            "11111111-1111-4111-8111-111111111111".into(),
            "management_write",
        );
        audit.identify_service("test-source");
        audit.target("resource-one");
        audit.operation(uuid::Uuid::from_u128(1), "management_write");
        audit.finalize(None);
        audit
    }
    fn time(value: i64) -> Timepoint {
        Timepoint::try_from(value).unwrap()
    }
    #[test]
    fn business_retry_recovers_source_time_but_never_accepts_changed_facts() {
        let first = Fact::business(
            &context(),
            "operation-one",
            b"original input",
            200,
            "success",
            None,
        )
        .unwrap();
        let retry = Fact::business(
            &context(),
            "operation-one",
            b"original input",
            200,
            "success",
            None,
        )
        .unwrap();
        let changed = Fact::business(
            &context(),
            "operation-one",
            b"changed input",
            200,
            "success",
            None,
        )
        .unwrap();
        let original = FrozenFact::freeze(&first, time(10)).unwrap();
        let candidate = FrozenFact::freeze(&retry, time(100)).unwrap();
        assert!(original.same_facts(&candidate));
        assert_ne!(original.bytes(), candidate.bytes());
        assert!(!original.same_facts(&FrozenFact::freeze(&changed, time(100)).unwrap()));
        let restored = FrozenFact::decode(original.bytes()).unwrap();
        let record = rss_audit_core::decode_untrusted(
            restored.prepare(time(150)).unwrap().canonical_bytes(),
        )
        .unwrap();
        assert_eq!(record.event().facts().occurred_at(), time(10));
        assert_eq!(record.recorded_at(), time(150));
        let altered = original
            .bytes()
            .iter()
            .copied()
            .chain([b' '])
            .collect::<Vec<_>>();
        assert!(FrozenFact::decode(&altered).is_err());
    }
    #[test]
    fn completion_and_business_do_not_share_an_outbox_partition() {
        let audit = context();
        let business = FrozenFact::freeze(
            &Fact::business(&audit, "write", b"input", 200, "success", None).unwrap(),
            time(10),
        )
        .unwrap();
        let completion =
            FrozenFact::freeze(&Fact::request(&audit, 200, "success").unwrap(), time(10)).unwrap();
        assert_ne!(
            business.partition().unwrap(),
            completion.partition().unwrap()
        );
        assert_eq!(
            business.partition().unwrap(),
            partition(
                business.identity().unwrap().tenant(),
                &business.source.resource_kind,
                &business.source.resource
            )
            .unwrap()
        );
    }
    #[test]
    fn ambiguous_failed_response_can_use_reserve_without_claiming_business_failure() {
        let audit = context();
        let unknown =
            FrozenFact::freeze(&Fact::request(&audit, 503, "unknown").unwrap(), time(10)).unwrap();
        let accepted =
            FrozenFact::freeze(&Fact::request(&audit, 202, "unknown").unwrap(), time(10)).unwrap();
        assert!(unknown.reserve_eligible());
        assert!(!accepted.reserve_eligible());
        assert!(matches!(unknown.source.outcome, SourceOutcome::Unknown));
    }
}
