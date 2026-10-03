//! Transport addresses are owned by management HTTP, not execution storage.
use rss_mdm_execution_service::queries::records::{
    CommandDetail, ExecutionDirectory, ExecutionEvidence, ExecutionKind, NativeObservation, RemoteDirectory,
};
use serde_json::{Value, json};
pub fn directory(facts: ExecutionDirectory) -> Value {
    let urls = facts
        .items
        .iter()
        .map(|item| match item.metadata.kind {
            ExecutionKind::Command => {
                let device = url::form_urlencoded::byte_serialize(item.metadata.device.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20");
                format!("/api/v3/devices/{device}/operations/{}", item.metadata.id)
            }
            ExecutionKind::ActionRun => {
                if let Some(policy) = item.metadata.policy {
                    format!("/api/v2/policies/{policy}/runs/{}", item.metadata.id)
                } else {
                    format!(
                        "/api/v3/remote-operations/{}/runs/{}",
                        item.metadata.remote_operation.expect("stored run source"),
                        item.metadata.id
                    )
                }
            }
        })
        .collect::<Vec<_>>();
    let observations = facts.items.iter().map(|item| match &item.evidence {
        ExecutionEvidence::Command(command) => Some(observation(&command.observation)),
        ExecutionEvidence::Run(_) => None,
    }).collect::<Vec<_>>();
    let mut value = serde_json::to_value(facts).expect("directory facts serialize");
    for ((item, url), observation) in value["items"]
        .as_array_mut()
        .expect("typed page")
        .iter_mut()
        .zip(urls).zip(observations)
    {
        item["detailUrl"] = json!(url);
        if let Some(observation) = observation { item["evidence"]["observation"] = observation; }
    }
    value
}
pub fn remote_directory(facts: RemoteDirectory) -> Value {
    let urls = facts
        .items
        .iter()
        .map(|item| format!("/api/v3/remote-operations/{}", item.id))
        .collect::<Vec<_>>();
    let mut value = serde_json::to_value(facts).expect("directory facts serialize");
    for (item, url) in value["items"]
        .as_array_mut()
        .expect("typed page")
        .iter_mut()
        .zip(urls)
    {
        item["detailUrl"] = json!(url);
    }
    value
}

/// The HTTP owner renders native facts after Execution's common authorization and state composition.
pub fn command(facts: CommandDetail) -> Value {
    let native = observation(&facts.observation);
    let mut value = serde_json::to_value(facts).expect("command facts serialize");
    value["observation"] = native;
    value
}
fn optional<T: serde::Serialize>(value: &mut Value, name: &str, field: Option<&T>) {
    if let Some(field) = field { value[name] = json!(field); }
}
fn apple_receipts(rows: &[rss_mdm_apple_mdm::native::evidence::Receipt]) -> Value {
    Value::Array(rows.iter().map(|r| {
        let mut value = json!({"phase":r.phase,"state":r.state,"receivedAt":r.received_at,"accepted":r.accepted});
        optional(&mut value,"outcome",r.outcome.as_ref());
        optional(&mut value,"fields",r.fields.as_ref());
        value
    }).collect())
}
fn observation(facts: &NativeObservation) -> Value {
    use rss_mdm_apple_mdm::native::{evidence::{ReadEvidence, MutationProgress, PublicationState}, profiles::Verification};
    match facts {
        NativeObservation::Windows { receipts, progress, effect, reason } => {
            let mut value = json!({"protocol":"syncml","observationScope":"native_objects","receipts":receipts,"progress":progress,"effect":effect});
            optional(&mut value,"effectReason",reason.as_ref());
            value
        }
        NativeObservation::Declarations { facts, progress } => {
            let mut value = json!({"protocol":"mdm.apple","observationScope":"declarations","progress":progress,
                "synchronization":"unpublished","effect":"unverified","compliance":"unknown"});
            if let Some(facts) = facts {
                value["inputVersion"] = json!(facts.input_version);
                value["expected"] = facts.expected.clone();
                value["synchronization"] = json!(match facts.publication { PublicationState::Published=>"published",PublicationState::Withdrawn=>"withdrawn" });
                value["nativeStatus"] = json!(facts.status);
                optional(&mut value,"receivedAt",facts.received_at.as_ref());
            }
            value
        }
        NativeObservation::Apple { facts, progress, effect_confirmed } => match facts {
            ReadEvidence::Command { receipts, outcome, fields, error } => {
                let mut value = json!({"protocol":"mdm.apple","observationScope":"native_command",
                    "receipts":apple_receipts(receipts),"progress":progress,"effect":"unverified"});
                optional(&mut value,"result",outcome.as_ref());
                optional(&mut value,"fields",fields.as_ref());
                optional(&mut value,"error",error.as_ref());
                value
            }
            ReadEvidence::Profile { receipts, progress, verification, status, received_at } => {
                let result = match verification {
                    Some(Verification::Matched) if *effect_confirmed => "matched",
                    Some(Verification::Mismatched | Verification::Failed) => "mismatched",
                    _ => "unknown",
                };
                let mut value = json!({"protocol":"mdm.apple","observationScope":"profile_presence",
                    "receipts":apple_receipts(receipts),"result":result,"effect":"unknown",
                    "progress":match progress { MutationProgress::Succeeded=>"succeeded",MutationProgress::Failed=>"failed",MutationProgress::Unknown=>"unknown" }});
                if let Some(status) = status {
                    use rss_mdm_apple_mdm::protocol::Status;
                    value["nativeStatus"] = json!(match status { Status::Idle=>"Idle",Status::Acknowledged=>"Acknowledged",Status::Error=>"Error",Status::NotNow=>"NotNow" });
                }
                optional(&mut value,"receivedAt",received_at.as_ref());
                value
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_mdm_apple_mdm::native::{ddm::StatusProjection, evidence::{DeclarationEvidence, PublicationState, ReadEvidence, MutationProgress}, profiles::Verification};
    #[test]
    fn declarations_preserve_the_public_projection() {
        let input = json!({"items":{},"unknownItems":[],"declarations":[],"errors":[],"completeness":"unknown","effect":"unverified","synchronized":false,"compliance":"unknown"});
        let status: StatusProjection = serde_json::from_value(input.clone()).unwrap();
        let value = observation(&NativeObservation::Declarations { progress:"received".into(), facts:Some(DeclarationEvidence {
            input_version:"v1".into(), expected:json!({"Configurations":[]}), publication:PublicationState::Published, received_at:None, status,
        }) });
        assert_eq!(value,json!({"protocol":"mdm.apple","observationScope":"declarations","progress":"received","effect":"unverified","compliance":"unknown","inputVersion":"v1","synchronization":"published","expected":{"Configurations":[]},"nativeStatus":input}));
    }
    #[test]
    fn native_profile_match_requires_common_effect_confirmation() {
        let mut facts = NativeObservation::Apple { progress:"received".into(), effect_confirmed:false,
            facts:ReadEvidence::Profile { receipts:vec![], progress:MutationProgress::Succeeded,
                verification:Some(Verification::Matched),status:None,received_at:None } };
        assert_eq!(observation(&facts)["result"],"unknown");
        if let NativeObservation::Apple { effect_confirmed, .. } = &mut facts { *effect_confirmed = true; }
        assert_eq!(observation(&facts)["result"],"matched");
    }
}
