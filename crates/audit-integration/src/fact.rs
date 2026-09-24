use crate::{RequestAudit, Snapshot};
use rss_audit_core::*;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::{RequestId, TenantId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Source-owned fact. A stable key identifies the operation and phase, never its outcome.
pub struct Fact {
    identity: RecordIdentity,
    snapshot: Snapshot,
    request: Option<Uuid>,
    payload: Vec<u8>,
    fingerprint: [u8; 32],
    outcome: Outcome,
}
#[derive(Debug, thiserror::Error)]
#[error("invalid product audit fact")]
pub struct InvalidFact;
impl Fact {
    pub fn business(
        context: &RequestAudit,
        key: &str,
        request_fingerprint: &[u8],
        status: u16,
        result: &str,
        registration: Option<Uuid>,
    ) -> Result<Self, InvalidFact> {
        let mut fact = Self::new(
            context,
            "mdm.business",
            key,
            None,
            status,
            result,
            registration,
        )?;
        if request_fingerprint.is_empty() {
            return Err(InvalidFact);
        }
        let mut hash = Sha256::new();
        hash.update(fact.fingerprint);
        hash.update(request_fingerprint);
        fact.fingerprint = hash.finalize().into();
        Ok(fact)
    }
    pub fn request(context: &RequestAudit, status: u16, result: &str) -> Result<Self, InvalidFact> {
        Self::new(
            context,
            "mdm.request",
            &context.request_id().to_string(),
            Some(context.request_id()),
            status,
            result,
            None,
        )
    }
    fn new(
        context: &RequestAudit,
        source: &str,
        key: &str,
        request: Option<Uuid>,
        status: u16,
        result: &str,
        registration: Option<Uuid>,
    ) -> Result<Self, InvalidFact> {
        if key.is_empty() || key.len() > 4096 || !(100..=599).contains(&status) {
            return Err(InvalidFact);
        }
        let snapshot = context.snapshot();
        let payload = serde_json::to_vec(&serde_json::json!({
            "status": status, "result": result, "instance": snapshot.instance,
            "operation": snapshot.operation_id, "registrationRequest": registration,
            "registration": snapshot.registration_id, "software": snapshot.software,
            "plan": snapshot.plan,
            "writeOutcome": request.map(|_| snapshot.write_outcome),
            "details": null,
        }))
        .map_err(|_| InvalidFact)?;
        let facts = serde_json::to_vec(&(
            context.tenant(),
            source,
            key,
            snapshot.actor.as_deref(),
            snapshot.actor_kind,
            snapshot.action,
            snapshot.target.as_deref(),
            &payload,
        ))
        .map_err(|_| InvalidFact)?;
        let fingerprint = Sha256::digest(&facts).into();
        let source = SourceIdentity::new(SourceId::parse(source).map_err(|_| InvalidFact)?, SourceContract::new(
            ContractId::parse("mdm.audit.fact").map_err(|_| InvalidFact)?,
            ContractVersion::from_major(1).map_err(|_| InvalidFact)?,
            SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(b"mdm.audit.fact.v1:status,result,instance,operation,registrationRequest,registration,software,plan,writeOutcome,details"))).map_err(|_| InvalidFact)?,
        ));
        let identity = RecordIdentity::new(
            TenantId::parse(context.tenant()).map_err(|_| InvalidFact)?,
            source,
            EventId::parse(&format!("e-{:x}", Sha256::digest(key.as_bytes())))
                .map_err(|_| InvalidFact)?,
        );
        let outcome = match result {
            "unknown" => Outcome::Unknown,
            "denied" | "rejected" if status == 401 || status == 403 => Outcome::Denied,
            "failed" | "denied" | "rejected" => Outcome::Failed,
            "success" | "replay" => Outcome::Succeeded,
            _ => return Err(InvalidFact),
        };
        Ok(Self {
            identity,
            snapshot,
            request,
            payload,
            fingerprint,
            outcome,
        })
    }
    /// Add source-owned, safe business fields before preparing immutable canonical bytes.
    pub fn with_details(mut self, details: serde_json::Value) -> Result<Self, InvalidFact> {
        let mut payload: serde_json::Value =
            serde_json::from_slice(&self.payload).map_err(|_| InvalidFact)?;
        payload["details"] = details;
        self.payload = serde_json::to_vec(&payload).map_err(|_| InvalidFact)?;
        let mut hash = Sha256::new();
        hash.update(self.fingerprint);
        hash.update(&self.payload);
        self.fingerprint = hash.finalize().into();
        Ok(self)
    }
    pub fn identity(&self) -> &RecordIdentity {
        &self.identity
    }
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    pub fn event(&self, observed_at: Timepoint) -> Result<AuditEventV1, InvalidFact> {
        let actor = self.snapshot.actor.as_deref().unwrap_or("unidentified");
        let resource = self.snapshot.target.as_deref().unwrap_or("request");
        Ok(AuditEventV1::new(
            self.identity.clone(),
            EventFacts::new(
                ActorRef::new(
                    ActorKind::parse(self.snapshot.actor_kind).map_err(|_| InvalidFact)?,
                    ActorId::parse(actor).map_err(|_| InvalidFact)?,
                ),
                Action::parse(self.snapshot.action).map_err(|_| InvalidFact)?,
                ResourceRef::new(
                    ResourceKind::parse("mdm").map_err(|_| InvalidFact)?,
                    ResourceId::parse(resource).map_err(|_| InvalidFact)?,
                ),
                self.outcome,
                observed_at,
            ),
            EventContext::new(
                Coordinates::new(
                    None,
                    self.request
                        .map(|v| RequestId::parse(&v.to_string()))
                        .transpose()
                        .map_err(|_| InvalidFact)?,
                    self.snapshot
                        .operation_id
                        .map(|v| OperationId::parse(&v.to_string()))
                        .transpose()
                        .map_err(|_| InvalidFact)?,
                ),
                AuditPayload::new(self.payload.clone()).map_err(|_| InvalidFact)?,
            ),
        ))
    }
}
