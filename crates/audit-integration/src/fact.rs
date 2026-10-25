use crate::{RequestAudit, Snapshot};
use rss_audit_core::*;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::{RequestId, TenantId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const SOURCE_SCHEMA: &[u8] = b"mdm.audit.fact.v1:status,result,instance,operation,registrationRequest,registration,software,plan,writeOutcome,details,sensitiveAction";

/// Source-owned fact. A stable key identifies the operation and phase, never its outcome.
pub struct Fact {
    identity: RecordIdentity,
    snapshot: Snapshot,
    request: Option<Uuid>,
    payload: Vec<u8>,
    outcome: Outcome,
}
/// Closed producer-contract errors; never contain tenant, actor, key or payload values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidFact {
    #[error("invalid audit tenant")]
    Tenant,
    #[error("invalid audit identity")]
    Identity,
    #[error("invalid audit status")]
    Status,
    #[error("invalid audit outcome")]
    Outcome,
    #[error("invalid audit actor")]
    Actor,
    #[error("invalid audit action")]
    Action,
    #[error("invalid audit resource")]
    Resource,
    #[error("invalid audit coordinates")]
    Coordinates,
    #[error("invalid audit payload")]
    Payload,
    #[error("invalid audit source contract")]
    Contract,
}
impl Fact {
    /// Canonical current product fact identity, shared by its real consumers.
    pub fn schema_digest() -> Result<SchemaDigest, InvalidFact> {
        SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(SOURCE_SCHEMA)))
            .map_err(|_| InvalidFact::Contract)
    }

    pub fn business(
        context: &RequestAudit,
        key: &str,
        status: u16,
        result: &str,
        registration: Option<Uuid>,
    ) -> Result<Self, InvalidFact> {
        Self::new(
            context,
            "mdm.business",
            key,
            None,
            status,
            result,
            registration,
        )
    }
    pub fn request(context: &RequestAudit, status: u16, result: &str) -> Result<Self, InvalidFact> {
        let fact = Self::new(
            context,
            "mdm.request",
            &context.request_id().to_string(),
            Some(context.request_id()),
            status,
            result,
            None,
        )?;
        match fact.snapshot.device_target.clone() {
            Some(device) => fact.with_details(serde_json::json!({"deviceId":device})),
            None => Ok(fact),
        }
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
        if key.is_empty() || key.len() > 4096 {
            return Err(InvalidFact::Identity);
        }
        if !(100..=599).contains(&status) {
            return Err(InvalidFact::Status);
        }
        let snapshot = context.snapshot();
        let payload = serde_json::to_vec(&serde_json::json!({
            "status": status, "result": result, "instance": snapshot.instance,
            "operation": snapshot.operation_id, "registrationRequest": registration,
            "registration": snapshot.registration_id, "software": snapshot.software,
            "plan": snapshot.plan,
            "writeOutcome": request.map(|_| snapshot.write_outcome),
            "details": null,
            "sensitiveAction": match snapshot.intent { crate::AuditIntent::Sensitive(action) => Some(action.as_str()), _ => None },
        }))
        .map_err(|_| InvalidFact::Payload)?;
        let source = SourceIdentity::new(
            SourceId::parse(source).map_err(|_| InvalidFact::Contract)?,
            SourceContract::new(
                ContractId::parse("mdm.audit.fact").map_err(|_| InvalidFact::Contract)?,
                ContractVersion::from_major(1).map_err(|_| InvalidFact::Contract)?,
                Self::schema_digest()?,
            ),
        );
        let identity = RecordIdentity::new(
            TenantId::parse(context.tenant()).map_err(|_| InvalidFact::Tenant)?,
            source,
            EventId::parse(&format!("e-{:x}", Sha256::digest(key.as_bytes())))
                .map_err(|_| InvalidFact::Identity)?,
        );
        let outcome = match result {
            "unknown" => Outcome::Unknown,
            "denied" | "rejected" if status == 401 || status == 403 => Outcome::Denied,
            "failed" | "denied" | "rejected" => Outcome::Failed,
            "success" | "replay" => Outcome::Succeeded,
            _ => return Err(InvalidFact::Outcome),
        };
        Ok(Self {
            identity,
            snapshot,
            request,
            payload,
            outcome,
        })
    }
    /// Add source-owned, safe business fields before preparing immutable canonical bytes.
    pub fn with_details(mut self, details: serde_json::Value) -> Result<Self, InvalidFact> {
        let mut payload: serde_json::Value =
            serde_json::from_slice(&self.payload).map_err(|_| InvalidFact::Payload)?;
        payload["details"] = details;
        self.payload = serde_json::to_vec(&payload).map_err(|_| InvalidFact::Payload)?;
        Ok(self)
    }
    pub fn identity(&self) -> &RecordIdentity {
        &self.identity
    }
    pub fn event(&self, observed_at: Timepoint) -> Result<AuditEventV1, InvalidFact> {
        let actor = self.snapshot.actor.as_deref().unwrap_or("unidentified");
        let resource = self.snapshot.target.as_deref().unwrap_or("request");
        Ok(AuditEventV1::new(
            self.identity.clone(),
            EventFacts::new(
                ActorRef::new(
                    ActorKind::parse(self.snapshot.actor_kind).map_err(|_| InvalidFact::Actor)?,
                    ActorId::parse(actor).map_err(|_| InvalidFact::Actor)?,
                ),
                Action::parse(self.snapshot.action).map_err(|_| InvalidFact::Action)?,
                ResourceRef::new(
                    ResourceKind::parse(self.snapshot.target_type)
                        .map_err(|_| InvalidFact::Resource)?,
                    ResourceId::parse(resource).map_err(|_| InvalidFact::Resource)?,
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
                        .map_err(|_| InvalidFact::Coordinates)?,
                    self.snapshot
                        .operation_id
                        .map(|v| OperationId::parse(&v.to_string()))
                        .transpose()
                        .map_err(|_| InvalidFact::Coordinates)?,
                ),
                AuditPayload::new(self.payload.clone()).map_err(|_| InvalidFact::Payload)?,
            ),
        ))
    }
}
