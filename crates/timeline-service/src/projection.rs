//! Typed extension seam: source-owned mappings project existing facts; no state is inferred.
use crate::{Error, FactView};
use rss_audit_core::{AuditEventV1, Outcome};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub fn project(event: &AuditEventV1) -> Result<FactView, Error> {
    let source = event.identity().source();
    let contract = source.contract();
    let digest=format!("sha256:{:x}",Sha256::digest(b"mdm.audit.fact.v1:status,result,instance,operation,registrationRequest,registration,software,plan,writeOutcome,details"));
    let supported = matches!(source.source_id().as_str(), "mdm.business" | "mdm.request")
        && contract.id().as_str() == "mdm.audit.fact"
        && contract.version().major() == 1
        && contract.schema_digest().as_str() == digest;
    let payload: Value = if supported {
        serde_json::from_slice(event.context().payload().as_bytes())
            .map_err(|_| Error::Integrity)?
    } else {
        Value::Null
    };
    let uuid = |key: &str| -> Result<Option<Uuid>, Error> {
        match payload.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(v)) => Uuid::parse_str(v).map(Some).map_err(|_| Error::Integrity),
            _ => Err(Error::Integrity),
        }
    };
    let action = event.facts().action().as_str();
    let request = source.source_id().as_str() == "mdm.request";
    let phase = if !supported {
        "unknown"
    } else if request {
        "request"
    } else {
        phase(action)
    };
    let write = if request && supported {
        match payload.get("writeOutcome") {
            None | Some(Value::Null) => None,
            Some(Value::String(v))
                if matches!(
                    v.as_str(),
                    "commit_not_started"
                        | "committed"
                        | "rolled_back"
                        | "rollback_failed"
                        | "unknown"
                ) =>
            {
                Some(v.clone())
            }
            _ => return Err(Error::Integrity),
        }
    } else {
        None
    };
    // Recovery records explicitly contain an execution transition, but not verified effect.
    let execution = if supported && action == "command_reconcile" {
        payload
            .pointer("/details/after/execution")
            .and_then(Value::as_str)
    } else {
        None
    };
    let phase = match execution {
        Some("running") => "executing",
        Some("unknown") => "unknown",
        Some("failed" | "succeeded") => "execution_result",
        Some("waiting_reboot") => "waiting_reboot",
        _ => phase,
    };
    Ok(FactView {
        source: source.source_id().as_str().into(),
        event_id: event.identity().event_id().as_str().into(),
        position: 0,
        recorded_at: 0,
        observed_at: event.facts().occurred_at().unix_seconds(),
        actor_kind: event.facts().actor().kind().as_str().into(),
        actor: event.facts().actor().id().as_str().into(),
        action: action.into(),
        target: (supported && phase != "unknown")
            .then(|| event.facts().resource().id().as_str().to_owned()),
        operation_id: event
            .context()
            .coordinates()
            .operation_id()
            .map(|v| Uuid::parse_str(v.as_str()))
            .transpose()
            .map_err(|_| Error::Integrity)?,
        related_operation_ids: Vec::new(),
        request_id: event
            .context()
            .coordinates()
            .request_id()
            .map(|v| Uuid::parse_str(v.as_str()))
            .transpose()
            .map_err(|_| Error::Integrity)?,
        registration_id: uuid("registration")?,
        registration_request_id: uuid("registrationRequest")?,
        instance_id: uuid("instance")?,
        audit_outcome: match event.facts().outcome() {
            Outcome::Succeeded => "succeeded",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
            Outcome::Unknown => "unknown",
        }
        .into(),
        phase: phase.into(),
        execution_state: execution
            .filter(|v| {
                matches!(
                    *v,
                    "not_started"
                        | "running"
                        | "succeeded"
                        | "failed"
                        | "waiting_reboot"
                        | "unknown"
                )
            })
            .map(str::to_owned),
        effect: "unknown".into(),
        request_write_outcome: write,
        supported,
    })
}
fn phase(action: &str) -> &'static str {
    match action {
        "registration_bind" => "registration",
        "credential_revoke" => "credential_revocation",
        "enrollment_create" | "enrollment_issue" | "enrollment_read" | "enrollment_resume"
        | "enrollment_cancel" => "enrollment",
        "inventory_read" => "inventory_read",
        "management_write" => "management",
        "management_read" => "management_read",
        "collection_start" => "collection_accepted",
        "collection_finish" => "collection_result",
        "command_accept" | "device_action" => "accepted",
        "command_approve" => "approved",
        "command_dispatch" => "dispatched",
        "command_cancel" => "cancellation",
        "command_reconcile" => "reconciliation",
        "command_read" => "operation_read",
        "authorization_write" | "authorization_initialize" => "authorization",
        _ => "unknown",
    }
}
