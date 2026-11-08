//! Typed extension seam: source-owned mappings project existing facts; no state is inferred.
use crate::{Error, FactView};
use rss_audit_core::{AuditEventV1, Outcome};
use serde_json::Value;
use uuid::Uuid;
pub fn project(event: &AuditEventV1) -> Result<FactView, Error> {
    let source = event.identity().source();
    let contract = source.contract();
    let digest = rss_mdm_audit_integration::Fact::schema_digest().map_err(|_| Error::Integrity)?;
    let product_envelope = matches!(
        source.source_id().as_str(),
        "mdm.business" | "mdm.request" | "da.business" | "da.request"
    ) && contract.id().as_str() == "mdm.audit.fact"
        && contract.version().major() == 1;
    let supported = product_envelope && contract.schema_digest().as_str() == digest.as_str();
    // Stable V1 envelope coordinates remain evidence even when a historical payload has no
    // current operation locator. No event hash or current resource reconstructs missing links.
    let payload: Value = if product_envelope {
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
    let request = matches!(source.source_id().as_str(), "mdm.request" | "da.request");
    let origin = if supported {
        Some(
            serde_json::from_value::<rss_mdm_audit_integration::Origin>(
                payload.get("origin").cloned().ok_or(Error::Integrity)?,
            )
            .map_err(|_| Error::Integrity)?,
        )
    } else {
        None
    };
    let phase = if !supported {
        "unknown"
    } else if request && origin == Some(rss_mdm_audit_integration::Origin::Background) {
        "background_attempt"
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
    let device_id = if supported {
        let device = payload
            .get("device")
            .filter(|value| !value.is_null())
            .or_else(|| {
                (request && action == "management_write")
                    .then(|| payload.pointer("/details/deviceId"))
                    .flatten()
            });
        match device {
            None | Some(Value::Null) => None,
            Some(Value::String(device)) if crate::model::identifier(device) => Some(device.clone()),
            _ => return Err(Error::Integrity),
        }
    } else {
        None
    };
    Ok(FactView {
        origin,
        source: source.source_id().as_str().into(),
        event_id: event.identity().event_id().as_str().into(),
        position: 0,
        recorded_at: 0,
        observed_at: event.facts().occurred_at().unix_seconds(),
        actor_kind: event.facts().actor().kind().as_str().into(),
        actor: event.facts().actor().id().as_str().into(),
        action: action.into(),
        target: crate::model::Target {
            kind: event.facts().resource().kind().as_str().into(),
            id: event.facts().resource().id().as_str().into(),
        },
        device_id,
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
        request_replayed: supported
            && request
            && origin == Some(rss_mdm_audit_integration::Origin::Request)
            && payload.get("result").and_then(Value::as_str) == Some("replay"),
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
        "command_reauthorize" => "reauthorized",
        "command_dispatch" => "dispatched",
        "command_cancel" => "cancellation",
        "command_reconcile" => "reconciliation",
        "command_read" => "operation_read",
        "authorization_write" | "authorization_initialize" => "authorization",
        _ => "unknown",
    }
}

/// Read only the current source-owned locator; event-key spelling is not a protocol.
pub(crate) fn operation_locator(
    event: &AuditEventV1,
    view: &FactView,
) -> Result<Option<rss_mdm_audit_integration::operation::OperationLocator>, Error> {
    if !view.supported {
        return Ok(None);
    }
    let payload: Value = serde_json::from_slice(event.context().payload().as_bytes())
        .map_err(|_| Error::Integrity)?;
    let locator: Option<rss_mdm_audit_integration::operation::OperationLocator> =
        serde_json::from_value(
            payload
                .get("operationLocator")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .map_err(|_| Error::Integrity)?;
    if let Some(locator) = &locator
        && (event
            .identity()
            .source()
            .source_id()
            .as_str()
            .starts_with("da.")
            != (locator.product == rss_mdm_audit_integration::StorageProfile::Da)
            || Some(locator.operation_id) != view.operation_id
            || locator.operation_id.is_nil()
            || !locator.owner.invocation()
                && locator.actor.as_deref() != Some(view.actor.as_str())
                && locator.actor.is_some()
            || locator.instance.is_some() && locator.instance != view.instance_id)
    {
        return Err(Error::Integrity);
    }
    Ok(locator)
}
