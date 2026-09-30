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
    let device_id = if supported && request && action == "management_write" {
        match payload.pointer("/details/deviceId") {
            None | Some(Value::Null) => None,
            Some(Value::String(device)) if crate::model::identifier(device) => Some(device.clone()),
            _ => return Err(Error::Integrity),
        }
    } else {
        None
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

/// Match the source owner's stable fact keys before interpreting an operation UUID.
/// Unrecognized identities retain their source coordinates without a guessed association.
pub(crate) fn execution_identity(
    event: &AuditEventV1,
    view: &FactView,
) -> Result<Option<rss_mdm_flow_service::execution::timeline::Identity>, Error> {
    use rss_mdm_flow_service::execution::timeline::Identity;
    if !view.supported {
        return Ok(None);
    }
    let Some(id) = view.operation_id else {
        return Ok(None);
    };
    if matches!(view.action.as_str(), "command_cancel" | "command_approve") {
        return Ok(Some(Identity::ChangeRequest(id)));
    }
    if view.source != "mdm.business" {
        return Ok(None);
    }
    let matches = |key: &str| view.event_id == format!("e-{:x}", Sha256::digest(key.as_bytes()));
    let identity = match view.action.as_str() {
        "command_accept" if matches(&format!("action:{id}:accept")) => {
            Some(Identity::ActionRun(id))
        }
        "command_accept" if matches(&format!("command:{}:{id}:accept", view.actor)) => {
            Some(Identity::Operation(id))
        }
        "command_dispatch" if matches(&format!("action:{id}:dispatch")) => {
            Some(Identity::ActionRun(id))
        }
        "command_dispatch" if matches(&format!("command:{id}:dispatch")) => {
            Some(Identity::Operation(id))
        }
        "command_reconcile" => {
            let payload: Value = serde_json::from_slice(event.context().payload().as_bytes())
                .map_err(|_| Error::Integrity)?;
            if let Some(version) = payload.pointer("/details/version").and_then(Value::as_u64)
                && matches(&format!("command:{id}:recover:{version}"))
            {
                Some(Identity::Operation(id))
            } else {
                use rss_mdm_flow_service::execution::actions::state::RunState;
                let states = payload.get("details").and_then(|d| {
                    Some((
                        serde_json::from_value::<RunState>(d.get("before")?.clone()).ok()?,
                        serde_json::from_value::<RunState>(d.get("after")?.clone()).ok()?,
                    ))
                });
                match states {
                    Some(states)
                        if matches(&format!(
                            "action:{id}:recover:{:x}",
                            Sha256::digest(
                                serde_json::to_vec(&states).map_err(|_| Error::Integrity)?
                            )
                        )) =>
                    {
                        Some(Identity::ActionRun(id))
                    }
                    _ => None,
                }
            }
        }
        _ => None,
    };
    Ok(identity)
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use rss_mdm_audit_integration::{Fact, RequestAudit};
    use rss_mdm_flow_service::execution::timeline::Identity;
    const TENANT: &str = "11111111-1111-4111-8111-111111111111";
    fn resolve(action: &'static str, key: &str, id: Uuid, details: Value) -> Option<Identity> {
        let audit = RequestAudit::new(TENANT.into(), action);
        audit.identify_service("fixture");
        audit.operation(id, action);
        let event = Fact::business(&audit, key, b"input", 200, "success", None)
            .unwrap()
            .with_details(details)
            .unwrap()
            .event(rss_contract::Timepoint::try_from(5i64).unwrap())
            .unwrap();
        let view = project(&event).unwrap();
        let identity = execution_identity(&event, &view).unwrap();
        audit.finalize(None);
        identity
    }
    #[test]
    fn same_uuid_resolves_only_in_its_producer_namespace() {
        let id = Uuid::new_v4();
        for (action, key, expected) in [
            (
                "command_accept",
                format!("command:fixture:{id}:accept"),
                Identity::Operation(id),
            ),
            (
                "command_accept",
                format!("action:{id}:accept"),
                Identity::ActionRun(id),
            ),
            (
                "command_dispatch",
                format!("command:{id}:dispatch"),
                Identity::Operation(id),
            ),
            (
                "command_dispatch",
                format!("action:{id}:dispatch"),
                Identity::ActionRun(id),
            ),
            (
                "command_cancel",
                "change".into(),
                Identity::ChangeRequest(id),
            ),
            (
                "command_approve",
                "change".into(),
                Identity::ChangeRequest(id),
            ),
        ] {
            assert_eq!(resolve(action, &key, id, Value::Null), Some(expected));
        }
        assert_eq!(
            resolve("command_accept", "unrecognized", id, Value::Null),
            None
        );
        assert_eq!(
            resolve(
                "command_reconcile",
                &format!("command:{id}:recover:3"),
                id,
                serde_json::json!({"version":3})
            ),
            Some(Identity::Operation(id))
        );
    }
    #[test]
    fn action_recovery_retains_its_namespace_and_request_accept_does_not_guess() {
        use rss_mdm_flow_service::execution::actions::state::{Execution, RunState};
        let id = Uuid::new_v4();
        let before = RunState::new(100, 1).unwrap();
        let mut after = before.clone();
        after.execution = Execution::Running;
        let key = format!(
            "action:{id}:recover:{:x}",
            Sha256::digest(serde_json::to_vec(&(&before, &after)).unwrap())
        );
        assert_eq!(
            resolve(
                "command_reconcile",
                &key,
                id,
                serde_json::json!({"before":before,"after":after})
            ),
            Some(Identity::ActionRun(id))
        );
        let audit = RequestAudit::new(TENANT.into(), "command_accept");
        audit.operation(id, "command_accept");
        let event = Fact::request(&audit, 202, "success")
            .unwrap()
            .event(rss_contract::Timepoint::try_from(5i64).unwrap())
            .unwrap();
        assert_eq!(
            execution_identity(&event, &project(&event).unwrap()).unwrap(),
            None
        );
        audit.finalize(None);
    }
}
