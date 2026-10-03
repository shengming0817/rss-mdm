use rss_mdm_agent_wire::*;
use serde_json::json;
#[test]
fn a_hash_marker_cannot_stand_in_for_a_frozen_native_source() {
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let step = json!({"action":{"package":"Acme.App","version":"1","behavior":{"kind":"winget","installer":"installer","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}},"signatures":[],"reboot":"report","downgrade":"deny"},"artifacts":[{"key":"0/installer","length":1,"sha256":vec![1;32]}],"target":{"kind":"device"},"exportIdentity":"sha256.marker"});
    assert!(serde_json::from_value::<SoftwareTaskStep>(step).is_err());
}
#[test]
fn frozen_source_binds_tenant_material_and_scoped_credentials_without_a_token_field() {
    let context = SoftwareExecutionContext {
        revision: 1,
        os_version: [10, 0, 22621, 0],
        system_broker: true,
        interactive_user: None,
        source_credentials: vec![],
        msix_sideload: false,
        msix_unsigned: false,
    };
    let id = uuid::Uuid::new_v4();
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let action:SoftwareTaskAction=serde_json::from_value(json!({"package":"Acme.App","version":"1","behavior":{"kind":"winget","installer":"installer","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}},"signatures":[],"reboot":"report","downgrade":"deny"})).unwrap();
    let binding = SoftwareExportBinding {
        source: "enterprise".into(),
        tenant_id: id,
        ring: SoftwareExportRing::Pilot,
        publication: [1; 32],
        source_digest: [2; 32],
        resource: "acme".into(),
        resource_version: "v1".into(),
        resource_digest: [3; 32],
        definition_digest: [4; 32],
        document_sha256: [5; 32],
        dependencies: vec![],
        artifacts: vec![SoftwareExportArtifact {
            url:
                "https://mdm.example/software/native/sources/enterprise/artifacts/acme/v1/setup.msi"
                    .into(),
            length: 1024,
            sha256: [6; 32],
        }],
    };
    let mut step = SoftwareTaskStep {
        action,
        artifacts: vec![SoftwareTaskArtifact {
            key: "0/installer".into(),
            length: 1024,
            sha256: [6; 32],
        }],
        target: SoftwareExecutionTarget::Device,
        export: SoftwareTaskExport::Winget {
            binding: binding.clone(),
            uri:
                "https://mdm.example/software/native/sources/enterprise/pilot/exports/publication/"
                    .into(),
            identifier: "rss.publication".into(),
        },
    };
    step.export.validate_for(&step, id, &context).unwrap();
    assert!(
        step.export
            .validate_for(&step, uuid::Uuid::new_v4(), &context)
            .is_err()
    );
    step.artifacts[0].sha256 = [7; 32];
    assert!(step.export.validate_for(&step, id, &context).is_err());
    step.artifacts[0].sha256 = [6; 32];
    step.export = SoftwareTaskExport::Direct;
    assert!(step.export.validate_for(&step, id, &context).is_err());
    let mut native = serde_json::to_value(SoftwareTaskExport::Winget {
        binding,
        uri: "https://mdm.example/source/".into(),
        identifier: "rss.publication".into(),
    })
    .unwrap();
    native["token"] = json!("secret");
    assert!(serde_json::from_value::<SoftwareTaskExport>(native).is_err());
}

#[test]
fn invocation_schema_matches_literal_argument_and_environment_validation() {
    let canonical: serde_json::Value =
        serde_json::from_str(include_str!("../schema/task-payload-v5.schema.json")).unwrap();
    let schema =
        serde_json::json!({"$ref":"#/$defs/SoftwareTaskInvocation","$defs":canonical["$defs"]});
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    for (argument, key, value, accepted) in [
        ("line\nnext", "RSS_PARAM_", "tab\tvalue", true),
        ("nul\0", "RSS_PARAM_X", "value", false),
        ("ok", "RSS_PARAM_X", "nul\0", false),
        ("ok", "PATH", "value", false),
    ] {
        let invocation = serde_json::json!({"runAs":"system","arguments":[argument],"environment":{key:value},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
        assert_eq!(validator.is_valid(&invocation), accepted, "{invocation}");
        let action:SoftwareTaskAction=serde_json::from_value(serde_json::json!({"package":"App","version":"1","reboot":"report","downgrade":"deny","signatures":[],"behavior":{"kind":"msi","installer":"package","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}}})).unwrap();
        let id = uuid::Uuid::new_v4();
        let steps = vec![SoftwareTaskStep {
            action,
            artifacts: vec![SoftwareTaskArtifact {
                key: "0/package".into(),
                length: 3,
                sha256: [1; 32],
            }],
            target: SoftwareExecutionTarget::Device,
            export: SoftwareTaskExport::Direct,
        }];
        use sha2::{Digest, Sha256};
        let spec = SoftwareTaskSpec {
            wire_version: 5,
            tenant_id: id,
            device_id: "device".into(),
            platform: TaskPlatform::Windows,
            architecture: TaskArchitecture::X86_64,
            registration_id: id,
            generation: 1,
            task_id: id,
            attempt_id: id,
            permit: TaskPermit::Offer,
            expires_at: 100,
            execution_context: SoftwareExecutionContext {
                revision: 1,
                os_version: [10, 0, 22621, 0],
                system_broker: true,
                interactive_user: None,
                source_credentials: vec![],
                msix_sideload: false,
                msix_unsigned: false,
            },
            definition_digest: Sha256::digest(serde_json::to_vec(&steps).unwrap()).into(),
            steps,
            intent: SoftwareTaskIntent::Install,
            start_mode: SoftwareStartMode::Automatic,
        };
        assert_eq!(spec.validate().is_ok(), accepted);
    }
}
