use super::*;
use serde_json::{Value, json};
fn msi() -> Value {
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":300,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":"1.0","artifacts":{"installer":{"reference":"installer","origin":null,"length":3,"sha256":vec![2;32]}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"installer","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.0"}},"signatures":[{"artifact":"installer","mechanism":"authenticode","publisher":"Acme","evidence":{"reference":"verification","origin":null,"length":100,"sha256":vec![3;32]}}],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})
}
#[test]
fn native_requires_reviewed_exact_material_and_native_semantics() {
    let compile = |v: Value| {
        Package::compile(
            &serde_json::from_value::<r::SoftwareDefinition>(v).unwrap(),
            "https://mdm.test".into(),
        )
    };
    let package = compile(msi()).unwrap();
    assert_eq!(
        package.effect_identity(),
        "msi:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    );
    let task = serde_json::to_value(
        package
            .task(
                Uuid::new_v4(),
                &rss_mdm_native_protection::Protector::new(&[8; 32]).unwrap(),
                rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let encoded = task.to_string();
    assert!(encoded.contains("/api/v1/software/installations/"));
    assert!(!encoded.contains("/agent/enroll/"));
    for (pointer, value) in [
        ("/signatures", json!([])),
        ("/signatures/0/evidence", Value::Null),
        (
            "/dependencies",
            json!([{"resource":"dep","version":"v1","sha256":vec![4;32]}]),
        ),
        (
            "/behavior/install/environment",
            json!({"RSS_PARAM_MODE":"custom"}),
        ),
        ("/behavior/install/arguments", json!(["CUSTOM=1"])),
    ] {
        let mut spec = msi();
        *spec.pointer_mut(pointer).unwrap() = value;
        assert!(compile(spec).is_err(), "{pointer}");
    }
}
#[test]
fn pkg_manifest_identity_does_not_claim_observed_application_identity() {
    let package = Package {
        identity: Identity::Pkg {
            receipt: "com.acme.receipt".into(),
            version: "1.0".into(),
        },
        artifact: r::SoftwareArtifact {
            reference: "pkg".into(),
            origin: None,
            length: 10,
            sha256: [2; 32],
        },
        origin: "https://mdm.test".into(),
        timeout_seconds: 300,
        minimum_os: None,
    };
    let crate::Task::Macos {
        request: rss_mdm_apple_mdm::native::request::Request::Command { command },
    } = package
        .task(
            Uuid::new_v4(),
            &rss_mdm_native_protection::Protector::new(&[8; 32]).unwrap(),
            rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        )
        .unwrap()
    else {
        panic!("pkg")
    };
    assert!(
        !command
            .fields
            .to_plist()
            .unwrap()
            .contains_key("Configuration")
    );
    assert!(
        rss_mdm_apple_mdm::software::observation(&command)
            .unwrap()
            .is_none()
    );
}
#[test]
fn msix_observation_is_read_only_and_targets_exact_provisioned_version() {
    let package = Package {
        identity: Identity::Msix {
            family: "Acme.App_8wekyb3d8bbwe".into(),
            identity: r::MsixIdentity {
                name: "Acme.App".into(),
                publisher: "CN=Acme".into(),
                version: [1, 2, 3, 4],
                architecture: r::MsixArchitecture::X86_64,
                resource_id: String::new(),
            },
        },
        artifact: r::SoftwareArtifact {
            reference: "msix".into(),
            origin: None,
            length: 10,
            sha256: [2; 32],
        },
        origin: "https://mdm.test".into(),
        timeout_seconds: 300,
        minimum_os: Some([10, 0, 22621, 0]),
    };
    let read = package.observation().unwrap();
    assert!(read.read_only().unwrap());
    let value = serde_json::to_string(&read).unwrap();
    assert!(value.contains("Acme.App_1.2.3.4_x64__8wekyb3d8bbwe"));
    assert!(value.contains("IsProvisioned"));
    assert!(!value.contains("HostedInstall"));
}

#[test]
fn native_rejects_unrepresentable_approved_semantics_before_queueing() {
    let compile = |v: Value| {
        Package::compile(
            &serde_json::from_value::<r::SoftwareDefinition>(v).unwrap(),
            "https://mdm.test".into(),
        )
    };
    for (field, value) in [("reboot", json!("forbid")), ("downgrade", json!("allow"))] {
        let mut spec = msi();
        spec[field] = value;
        assert!(compile(spec).is_err());
    }
    for (seconds, accepted) in [(15300, true), (15301, false), (301, false)] {
        let mut spec = msi();
        for invocation in ["install", "upgradeInvocation"] {
            spec["behavior"][invocation]["timeoutSeconds"] = json!(seconds);
        }
        assert_eq!(compile(spec).is_ok(), accepted);
    }
    let mut spec = msi();
    for invocation in ["install", "upgradeInvocation"] {
        spec["behavior"][invocation]["exitCodes"]["success"] = json!([42]);
    }
    assert!(compile(spec).is_err());
}
