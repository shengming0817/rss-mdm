//! Aggregate evidence is checked against the mounted response, using real owner DTOs.
use crate::execution::{
    operations::{Detail, Evidence, Item, KindOfOperation, Metadata, Page},
    projection::{AppleObservation, CommandStatus, Observation, Unverified},
};
use configuration::queries::records::Detail as ConfigurationDetail;
use device::queries::records::CommandDetail as DeviceDetail;
use recovery::queries::Detail as RecoveryDetail;
use registration::queries::Detail as RegistrationDetail;
use rss_mdm_device_service::control as device;
use rss_mdm_policy_service::configuration;
use rss_mdm_recovery_credentials::native as recovery;
use rss_mdm_registration_service::installation as registration;
use rss_mdm_software_service::deployment as software;
use serde::Deserialize;
use serde_json::{Value, json};
use software::queries::records::CommandDetail as SoftwareDetail;
use uuid::Uuid;

fn observation() -> Observation {
    Observation::Apple {
        observation: Box::new(AppleObservation::NativeCommand {
            receipts: Vec::new(),
            progress: CommandStatus(rss_device_command::Status::Published),
            effect: Unverified::Unverified,
            result: None,
            fields: None,
            error: None,
        }),
    }
}

fn native_details() -> [(&'static str, Detail); 5] {
    macro_rules! detail {
        ($owner:ident, $record:ident, $authorization:expr, $status:expr $(, $field:ident: $value:expr)*) => {
            $record {
                operation_id: Uuid::from_u128(1),
                command_id: Uuid::from_u128(2),
                revision: 1,
                task: $owner::model::TaskSummary {
                    platform: rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
                    kind: $owner::model::TaskKind::Command,
                    name: "DeviceInformation".into(),
                    objects: vec!["DeviceName".into()],
                },
                target: $owner::NativeTarget::Device,
                input_version: "input-1".into(),
                deadline: 100,
                dispatch_failure: None,
                authorization: $authorization,
                command_status: $status,
                observation: observation(),
                $($field: $value,)*
            }
        };
    }
    [
        (
            "configuration",
            Detail::Configuration(detail!(
                configuration,
                ConfigurationDetail,
                configuration::queries::records::Authorization::Authorized,
                rss_device_command::Status::Published
            )),
        ),
        (
            "device",
            Detail::Device(detail!(
                device, DeviceDetail,
                device::authorization_decision::Authorization::Authorized,
                device::queries::records::CommandStatus(rss_device_command::Status::Published),
                reauthorization: device::authorization_decision::Reauthorization::NotApplicable
            )),
        ),
        (
            "software",
            Detail::Software(Box::new(detail!(
                software, SoftwareDetail,
                software::authorization_decision::Authorization::Authorized,
                software::queries::records::CommandStatus(rss_device_command::Status::Published),
                reauthorization: software::authorization_decision::Reauthorization::NotApplicable,
                agent_installation: None
            ))),
        ),
        (
            "recovery",
            Detail::Recovery(detail!(
                recovery, RecoveryDetail,
                recovery::queries::Authorization::Authorized,
                recovery::queries::CommandStatus(rss_device_command::Status::Published),
                reauthorization: recovery::queries::Reauthorization::NotApplicable
            )),
        ),
        (
            "registration",
            Detail::Registration(detail!(
                registration, RegistrationDetail,
                registration::queries::Authorization::Authorized,
                registration::queries::CommandStatus(rss_device_command::Status::Published),
                reauthorization: registration::queries::Reauthorization::NotApplicable
            )),
        ),
    ]
}

fn other_evidence() -> [(&'static str, Evidence); 5] {
    let state = rss_mdm_task_state::RunState::new(100, 1).unwrap();
    let run = json!({"state": state, "effect": "unknown", "result": null});
    let record = json!({
        "taskId": Uuid::from_u128(1), "policyId": Uuid::from_u128(2),
        "versionId": Uuid::from_u128(3), "device": "device-a",
        "occurrence": "once", "availableAt": 1, "deadline": 100,
        "state": state, "authorization": null, "attemptId": null, "result": null
    });
    [
        (
            "device",
            Evidence::Device(serde_json::from_value(run.clone()).unwrap()),
        ),
        (
            "software",
            Evidence::Software(serde_json::from_value(run).unwrap()),
        ),
        (
            "enrollment",
            Evidence::Enrollment(serde_json::from_value(record.clone()).unwrap()),
        ),
        (
            "access",
            Evidence::Access(serde_json::from_value(record.clone()).unwrap()),
        ),
        (
            "credential",
            Evidence::Credential(serde_json::from_value(record).unwrap()),
        ),
    ]
}

fn document() -> Value {
    let routes = crate::contract_routes(
        crate::Mounts {
            filevault: true,
            recovery_credentials: true,
        },
        super::application_routes(),
    );
    rss_mdm_http_contract::artifact::document([("browser", routes.into_endpoints())]).unwrap()
}

fn endpoint<'a>(document: &'a Value, path: &str) -> &'a Value {
    document["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["method"] == "GET" && e["path"] == path)
        .unwrap()
}

fn response_schema<'a>(document: &'a Value, path: &str) -> &'a Value {
    let response = endpoint(document, path)["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["status"] == 200)
        .unwrap();
    let identity = response["body"]["schema"]["schemaId"].as_str().unwrap();
    &document["schemas"][identity]
}

fn validator(document: &Value, path: &str) -> jsonschema::Validator {
    jsonschema::validator_for(response_schema(document, path)).unwrap()
}

fn page(evidence: Option<Evidence>, kind: KindOfOperation) -> Page<Item> {
    Page {
        items: vec![Item {
            metadata: Metadata {
                id: Uuid::from_u128(1),
                kind,
                device: "device-a".into(),

                origin: "direct".into(),
                policy: None,
                deadline: 100,
                status: "published".into(),
            },
            evidence,
            authorization: None,
            reauthorization: None,
            detail_url: "/api/v1/devices/device-a/operations/1".into(),
        }],
        next_cursor: None,
    }
}

// Derived deserialization rejects duplicate `owner` members before a Value can hide them.
#[derive(Deserialize)]
struct Owner {
    owner: String,
}
#[derive(Deserialize)]
struct NativeEnvelope {
    owner: String,
    detail: Owner,
}

#[test]
fn native_owners_serialize_without_conflicting_tags_and_match_mounted_schemas() {
    let document = document();
    let list = validator(&document, "/api/v1/operations");
    let detail_schema = validator(&document, "/api/v1/devices/{device}/operations/{id}");
    for (owner, detail) in native_details() {
        let bytes = serde_json::to_vec(&detail).unwrap();
        let detail_owner: Owner = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(detail_owner.owner, owner);
        let detail_value: Value = serde_json::from_slice(&bytes).unwrap();
        detail_schema.validate(&detail_value).unwrap();
        assert!(detail_value.get("detail").is_none());

        let evidence = Evidence::Native {
            detail: Box::new(detail),
        };
        let bytes = serde_json::to_vec(&evidence).unwrap();
        let envelope: NativeEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope.owner, "native");
        assert_eq!(envelope.detail.owner, owner);
        let mut value =
            serde_json::to_value(page(Some(evidence), KindOfOperation::Command)).unwrap();
        assert_eq!(value["items"][0]["evidence"]["detail"], detail_value);
        list.validate(&value).unwrap();

        let valid = value["items"][0]["evidence"].clone();
        for invalid in [
            json!({"owner": "native"}),
            json!({"owner": "native", "detail": {"owner": "unknown"}}),
            detail_value,
        ] {
            value["items"][0]["evidence"] = invalid;
            assert!(!list.is_valid(&value), "accepted malformed native evidence");
        }
        value["items"][0]["evidence"] = valid;
        value["items"][0]["evidence"]["detail"]
            .as_object_mut()
            .unwrap()
            .remove("owner");
        assert!(!list.is_valid(&value));
    }
}

#[test]
fn non_native_evidence_keeps_its_owner_and_projection_can_omit_evidence() {
    let document = document();
    let list = validator(&document, "/api/v1/operations");
    for (owner, evidence) in other_evidence() {
        let bytes = serde_json::to_vec(&evidence).unwrap();
        let decoded: Owner = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.owner, owner);
        let value = serde_json::to_value(page(Some(evidence), KindOfOperation::ActionRun)).unwrap();
        assert!(value["items"][0]["evidence"].get("detail").is_none());
        list.validate(&value).unwrap();
    }
    let value = serde_json::to_value(page(None, KindOfOperation::Command)).unwrap();
    assert!(value["items"][0].get("evidence").is_none());
    list.validate(&value).unwrap();
}

#[test]
fn registration_response_preserves_the_certificate_grant_field() {
    use rss_mdm_registration_service::enrollment::registration::Registration;
    let document = document();
    let path = "/api/v1/devices/{device}/registration";
    let grant = Uuid::from_u128(7);
    let row: Registration = serde_json::from_value(json!({
        "deviceId": "device-4", "source": "agent.builtin",
        "status": "active", "enrolledUser": false,
        "enrollmentId": null, "certificateGrantId": grant, "windowsDeclared": null
    }))
    .unwrap();
    let value = serde_json::to_value(row).unwrap();
    assert_eq!(value["certificateGrantId"], json!(grant));
    validator(&document, path).validate(&value).unwrap();
    assert!(value.get("registrationId").is_none());
    assert!(value.get("generation").is_none());
}
