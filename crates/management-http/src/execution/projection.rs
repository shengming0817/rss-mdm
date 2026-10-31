//! HTTP owns transport addresses and the actual native observation serialization.
use rss_mdm_apple_mdm::native::{
    evidence::{MutationProgress, PublicationState, ReadEvidence},
    profiles::Verification,
};
use rss_mdm_execution_service::queries::records::{self, CommandDetail, NativeObservation};
use serde::Serialize;
use uuid::Uuid;
pub fn command(facts: CommandDetail) -> CommandDetail<Observation> {
    CommandDetail {
        operation_id: facts.operation_id,
        command_id: facts.command_id,
        revision: facts.revision,
        task: facts.task,
        target: facts.target,
        input_version: facts.input_version,
        deadline: facts.deadline,
        dispatch_failure: facts.dispatch_failure,
        authorization: facts.authorization,
        reauthorization: facts.reauthorization,
        command_status: facts.command_status,
        observation: observation(facts.observation),
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "protocol")]
pub enum Observation {
    #[serde(rename = "syncml", rename_all = "camelCase")]
    Windows {
        observation_scope: NativeObjects,
        receipts: Vec<records::WindowsReceipt>,
        progress: records::CommandStatus,
        effect: rss_mdm_windows_mdm::native::verification::EffectState,
        #[serde(skip_serializing_if = "Option::is_none")]
        effect_reason: Option<&'static str>,
    },
    #[serde(rename = "mdm.apple")]
    Apple {
        #[serde(flatten)]
        observation: Box<AppleObservation>,
    },
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeObjects {
    NativeObjects,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(
    tag = "observationScope",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AppleObservation {
    Declarations {
        progress: records::CommandStatus,
        synchronization: Synchronization,
        effect: Unverified,
        compliance: Unknown,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_version: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected: Option<rss_mdm_apple_mdm::native::ddm::ManifestLists>,
        #[serde(skip_serializing_if = "Option::is_none")]
        native_status: Option<rss_mdm_apple_mdm::native::ddm::StatusProjection>,
        #[serde(skip_serializing_if = "Option::is_none")]
        received_at: Option<i64>,
    },
    NativeCommand {
        receipts: Vec<AppleReceipt>,
        progress: records::CommandStatus,
        effect: Unverified,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<rss_mdm_apple_mdm::native::outcome::Outcome>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fields: Option<rss_mdm_apple_mdm::native::input::Fields>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<rss_mdm_apple_mdm::native::input::Fields>,
    },
    ProfilePresence {
        receipts: Vec<AppleReceipt>,
        result: ProfileResult,
        effect: Unknown,
        progress: MutationProgress,
        #[serde(skip_serializing_if = "Option::is_none")]
        native_status: Option<rss_mdm_apple_mdm::protocol::Status>,
        #[serde(skip_serializing_if = "Option::is_none")]
        received_at: Option<i64>,
    },
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unverified {
    Unverified,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unknown {
    Unknown,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Synchronization {
    Unpublished,
    Published,
    Withdrawn,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfileResult {
    Matched,
    Mismatched,
    Unknown,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppleReceipt {
    phase: rss_mdm_apple_mdm::native::evidence::Phase,
    state: rss_mdm_apple_mdm::native::evidence::ReceiptState,
    received_at: Option<i64>,
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<rss_mdm_apple_mdm::native::outcome::Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<rss_mdm_apple_mdm::native::input::Fields>,
}
fn receipts(rows: Vec<rss_mdm_apple_mdm::native::evidence::Receipt>) -> Vec<AppleReceipt> {
    rows.into_iter()
        .map(|r| AppleReceipt {
            phase: r.phase,
            state: r.state,
            received_at: r.received_at,
            accepted: r.accepted,
            outcome: r.outcome,
            fields: r.fields,
        })
        .collect()
}
fn observation(facts: NativeObservation) -> Observation {
    match facts {
        NativeObservation::Windows {
            receipts,
            progress,
            effect,
            reason,
        } => Observation::Windows {
            observation_scope: NativeObjects::NativeObjects,
            receipts,
            progress,
            effect,
            effect_reason: reason,
        },
        NativeObservation::Declarations { facts, progress } => {
            let (synchronization, input_version, expected, native_status, received_at) =
                if let Some(facts) = facts {
                    (
                        match facts.publication {
                            PublicationState::Published => Synchronization::Published,
                            PublicationState::Withdrawn => Synchronization::Withdrawn,
                        },
                        Some(facts.input_version),
                        Some(facts.expected),
                        Some(facts.status),
                        facts.received_at,
                    )
                } else {
                    (Synchronization::Unpublished, None, None, None, None)
                };
            Observation::Apple {
                observation: Box::new(AppleObservation::Declarations {
                    progress,
                    synchronization,
                    effect: Unverified::Unverified,
                    compliance: Unknown::Unknown,
                    input_version,
                    expected,
                    native_status,
                    received_at,
                }),
            }
        }
        NativeObservation::Apple {
            facts,
            progress,
            effect_confirmed,
        } => Observation::Apple {
            observation: Box::new(match facts {
                ReadEvidence::Command {
                    receipts: rows,
                    outcome,
                    fields,
                    error,
                } => AppleObservation::NativeCommand {
                    receipts: receipts(rows),
                    progress,
                    effect: Unverified::Unverified,
                    result: outcome,
                    fields,
                    error,
                },
                ReadEvidence::Profile {
                    receipts: rows,
                    progress,
                    verification,
                    status,
                    received_at,
                } => {
                    let result = match verification {
                        Some(Verification::Matched) if effect_confirmed => ProfileResult::Matched,
                        Some(Verification::Mismatched | Verification::Failed) => {
                            ProfileResult::Mismatched
                        }
                        _ => ProfileResult::Unknown,
                    };
                    AppleObservation::ProfilePresence {
                        receipts: receipts(rows),
                        result,
                        effect: Unknown::Unknown,
                        progress,
                        native_status: status,
                        received_at,
                    }
                }
            }),
        },
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Ddm {
    items: Vec<DdmItem>,
    next_cursor: Option<String>,
    availability: Availability,
    effect: Unverified,
    compliance: Unknown,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    CurrentRegistration,
    NoCurrentRegistration,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DdmItem {
    operation_id: Uuid,
    registration_id: Uuid,
    generation: i64,
    channel: AppleChannel,
    user_key: String,
    native_values_redacted: bool,
    observation: Observation,
}
#[derive(Serialize, schemars::JsonSchema)]
enum AppleChannel {
    #[serde(rename = "mdm.apple")]
    Apple,
}
pub fn ddm(page: rss_mdm_execution_service::queries::ddm::Page) -> Ddm {
    let items = page
        .items
        .into_iter()
        .map(|item| DdmItem {
            operation_id: item.operation,
            registration_id: item.registration,
            generation: item.generation,
            channel: AppleChannel::Apple,
            user_key: item.user,
            native_values_redacted: item.redacted,
            observation: observation(item.observation),
        })
        .collect();
    Ddm {
        items,
        next_cursor: page.next_cursor,
        availability: if page.current_registration {
            Availability::CurrentRegistration
        } else {
            Availability::NoCurrentRegistration
        },
        effect: Unverified::Unverified,
        compliance: Unknown::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn declarations_preserve_the_public_projection_and_all_manifest_families() {
        let input = json!({"items":{},"unknownItems":[],"declarations":[],"errors":[],"completeness":"unknown","effect":"unverified","synchronized":false,"compliance":"unknown"});
        let facts = NativeObservation::Declarations {
            progress: serde_json::from_value(json!("received")).unwrap(),
            facts: Some(rss_mdm_apple_mdm::native::evidence::DeclarationEvidence {
                input_version: "v1".into(),
                expected: Default::default(),
                publication: PublicationState::Published,
                received_at: None,
                status: serde_json::from_value(input.clone()).unwrap(),
            }),
        };
        let value = serde_json::to_value(observation(facts)).unwrap();
        assert_eq!(
            value,
            json!({"protocol":"mdm.apple","observationScope":"declarations","progress":"received","effect":"unverified","compliance":"unknown","inputVersion":"v1","synchronization":"published","expected":{"Configurations":[],"Activations":[],"Assets":[],"Management":[]},"nativeStatus":input})
        );
        let schema = schemars::generate::SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<Observation>()
            .to_value();
        assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    }
    #[test]
    fn native_profile_match_requires_common_effect_confirmation_and_keeps_omission() {
        for (effect_confirmed, expected) in [(false, "unknown"), (true, "matched")] {
            let value = serde_json::to_value(observation(NativeObservation::Apple {
                progress: serde_json::from_value(json!("received")).unwrap(),
                effect_confirmed,
                facts: ReadEvidence::Profile {
                    receipts: vec![],
                    progress: MutationProgress::Succeeded,
                    verification: Some(Verification::Matched),
                    status: None,
                    received_at: None,
                },
            }))
            .unwrap();
            assert_eq!(value["result"], expected);
            assert_eq!(value["progress"], "succeeded");
            assert!(value.get("receivedAt").is_none());
            assert!(value.get("nativeStatus").is_none());
            assert_eq!(value["effect"], "unknown");
        }
    }
}

pub fn software_observation(
    facts: rss_mdm_software_service::deployment::queries::records::NativeObservation,
) -> Observation {
    match facts {
        rss_mdm_software_service::deployment::queries::records::NativeObservation::Windows {
            receipts,
            progress,
            effect,
            reason,
        } => Observation::Windows {
            observation_scope: NativeObjects::NativeObjects,
            receipts:receipts.into_iter().map(software_receipt).collect(),
            progress:records::CommandStatus(progress.0),
            effect,
            effect_reason: reason,
        },
        rss_mdm_software_service::deployment::queries::records::NativeObservation::Declarations { facts, progress } => {
            let (synchronization, input_version, expected, native_status, received_at) =
                if let Some(facts) = facts {
                    (
                        match facts.publication {
                            PublicationState::Published => Synchronization::Published,
                            PublicationState::Withdrawn => Synchronization::Withdrawn,
                        },
                        Some(facts.input_version),
                        Some(facts.expected),
                        Some(facts.status),
                        facts.received_at,
                    )
                } else {
                    (Synchronization::Unpublished, None, None, None, None)
                };
            Observation::Apple {
                observation: Box::new(AppleObservation::Declarations {
                    progress:records::CommandStatus(progress.0),
                    synchronization,
                    effect: Unverified::Unverified,
                    compliance: Unknown::Unknown,
                    input_version,
                    expected,
                    native_status,
                    received_at,
                }),
            }
        }
        rss_mdm_software_service::deployment::queries::records::NativeObservation::Apple {
            facts,
            progress,
            effect_confirmed,
        } => Observation::Apple {
            observation: Box::new(match facts {
                ReadEvidence::Command {
                    receipts: rows,
                    outcome,
                    fields,
                    error,
                } => AppleObservation::NativeCommand {
                    receipts: receipts(rows),
                    progress:records::CommandStatus(progress.0),
                    effect: Unverified::Unverified,
                    result: outcome,
                    fields,
                    error,
                },
                ReadEvidence::Profile {
                    receipts: rows,
                    progress,
                    verification,
                    status,
                    received_at,
                } => {
                    let result = match verification {
                        Some(Verification::Matched) if effect_confirmed => ProfileResult::Matched,
                        Some(Verification::Mismatched | Verification::Failed) => {
                            ProfileResult::Mismatched
                        }
                        _ => ProfileResult::Unknown,
                    };
                    AppleObservation::ProfilePresence {
                        receipts: receipts(rows),
                        result,
                        effect: Unknown::Unknown,
                        progress,
                        native_status: status,
                        received_at,
                    }
                }
            }),
        },
    }
}

fn software_receipt(
    r: rss_mdm_software_service::deployment::queries::records::WindowsReceipt,
) -> records::WindowsReceipt {
    records::WindowsReceipt {
        phase: match r.phase {
            rss_mdm_software_service::deployment::AttemptPhase::Prepare => {
                rss_mdm_execution_service::AttemptPhase::Prepare
            }
            rss_mdm_software_service::deployment::AttemptPhase::Execute => {
                rss_mdm_execution_service::AttemptPhase::Execute
            }
            rss_mdm_software_service::deployment::AttemptPhase::Observe => {
                rss_mdm_execution_service::AttemptPhase::Observe
            }
        },
        ordinal: r.ordinal,
        session: r.session,
        message: r.message,
        command: r.command,
        parent_command: r.parent_command,
        item: r.item,
        kind: r.kind,
        uri: r.uri,
        status: r.status,
        value: r.value,
        accepted: r.accepted,
        received_at: r.received_at,
        result_accepted: r.result_accepted,
        result_received_at: r.result_received_at,
        redacted: r.redacted,
        frames: r
            .frames
            .into_iter()
            .map(|f| records::WindowsFrame {
                message: f.message,
                command: f.command,
                start_byte: f.start_byte,
                end_byte: f.end_byte,
                total_bytes: f.total_bytes,
                status: f.status,
                accepted: f.accepted,
                received_at: f.received_at,
            })
            .collect(),
    }
}
pub fn software_command(
    v: rss_mdm_software_service::deployment::queries::records::CommandDetail,
) -> rss_mdm_software_service::deployment::queries::records::CommandDetail<Observation> {
    rss_mdm_software_service::deployment::queries::records::CommandDetail {
        operation_id: v.operation_id,
        command_id: v.command_id,
        revision: v.revision,
        task: v.task,
        target: v.target,
        input_version: v.input_version,
        deadline: v.deadline,
        dispatch_failure: v.dispatch_failure,
        authorization: v.authorization,
        reauthorization: v.reauthorization,
        command_status: v.command_status,
        agent_installation: v.agent_installation,
        observation: software_observation(v.observation),
    }
}

pub fn registration_observation(
    facts: rss_mdm_registration_service::installation::queries::NativeObservation,
) -> Observation {
    match facts {
        rss_mdm_registration_service::installation::queries::NativeObservation::Windows {
            receipts,
            progress,
            effect,
            reason,
        } => Observation::Windows {
            observation_scope: NativeObjects::NativeObjects,
            receipts: receipts.into_iter().map(registration_receipt).collect(),
            progress: records::CommandStatus(progress.0),
            effect,
            effect_reason: reason,
        },
        rss_mdm_registration_service::installation::queries::NativeObservation::Declarations {
            facts,
            progress,
        } => {
            let (synchronization, input_version, expected, native_status, received_at) =
                if let Some(facts) = facts {
                    (
                        match facts.publication {
                            PublicationState::Published => Synchronization::Published,
                            PublicationState::Withdrawn => Synchronization::Withdrawn,
                        },
                        Some(facts.input_version),
                        Some(facts.expected),
                        Some(facts.status),
                        facts.received_at,
                    )
                } else {
                    (Synchronization::Unpublished, None, None, None, None)
                };
            Observation::Apple {
                observation: Box::new(AppleObservation::Declarations {
                    progress: records::CommandStatus(progress.0),
                    synchronization,
                    effect: Unverified::Unverified,
                    compliance: Unknown::Unknown,
                    input_version,
                    expected,
                    native_status,
                    received_at,
                }),
            }
        }
        rss_mdm_registration_service::installation::queries::NativeObservation::Apple {
            facts,
            progress,
            effect_confirmed,
        } => Observation::Apple {
            observation: Box::new(match facts {
                ReadEvidence::Command {
                    receipts: rows,
                    outcome,
                    fields,
                    error,
                } => AppleObservation::NativeCommand {
                    receipts: receipts(rows),
                    progress: records::CommandStatus(progress.0),
                    effect: Unverified::Unverified,
                    result: outcome,
                    fields,
                    error,
                },
                ReadEvidence::Profile {
                    receipts: rows,
                    progress,
                    verification,
                    status,
                    received_at,
                } => {
                    let result = match verification {
                        Some(Verification::Matched) if effect_confirmed => ProfileResult::Matched,
                        Some(Verification::Mismatched | Verification::Failed) => {
                            ProfileResult::Mismatched
                        }
                        _ => ProfileResult::Unknown,
                    };
                    AppleObservation::ProfilePresence {
                        receipts: receipts(rows),
                        result,
                        effect: Unknown::Unknown,
                        progress,
                        native_status: status,
                        received_at,
                    }
                }
            }),
        },
    }
}

fn registration_receipt(
    r: rss_mdm_registration_service::installation::queries::WindowsReceipt,
) -> records::WindowsReceipt {
    records::WindowsReceipt {
        phase: match r.phase {
            rss_mdm_registration_service::installation::AttemptPhase::Prepare => {
                rss_mdm_execution_service::AttemptPhase::Prepare
            }
            rss_mdm_registration_service::installation::AttemptPhase::Execute => {
                rss_mdm_execution_service::AttemptPhase::Execute
            }
            rss_mdm_registration_service::installation::AttemptPhase::Observe => {
                rss_mdm_execution_service::AttemptPhase::Observe
            }
        },
        ordinal: r.ordinal,
        session: r.session,
        message: r.message,
        command: r.command,
        parent_command: r.parent_command,
        item: r.item,
        kind: r.kind,
        uri: r.uri,
        status: r.status,
        value: r.value,
        accepted: r.accepted,
        received_at: r.received_at,
        result_accepted: r.result_accepted,
        result_received_at: r.result_received_at,
        redacted: r.redacted,
        frames: r
            .frames
            .into_iter()
            .map(|f| records::WindowsFrame {
                message: f.message,
                command: f.command,
                start_byte: f.start_byte,
                end_byte: f.end_byte,
                total_bytes: f.total_bytes,
                status: f.status,
                accepted: f.accepted,
                received_at: f.received_at,
            })
            .collect(),
    }
}
pub fn registration_command(
    v: rss_mdm_registration_service::installation::queries::Detail,
) -> rss_mdm_registration_service::installation::queries::Detail<Observation> {
    rss_mdm_registration_service::installation::queries::Detail {
        operation_id: v.operation_id,
        command_id: v.command_id,
        revision: v.revision,
        task: v.task,
        target: v.target,
        input_version: v.input_version,
        deadline: v.deadline,
        dispatch_failure: v.dispatch_failure,
        authorization: v.authorization,
        reauthorization: v.reauthorization,
        command_status: v.command_status,
        observation: registration_observation(v.observation),
    }
}
