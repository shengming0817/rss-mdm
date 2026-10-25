use rss_mdm_agent_wire::runtime::*;
use serde_json::json;
#[test]
fn frozen_source_binds_tenant_material_and_scoped_credentials_without_a_token_field() {
    let id = uuid::Uuid::new_v4();
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let action:SoftwareTaskAction=serde_json::from_value(json!({"package":"Acme.App","version":"1","behavior":{"kind":"winget","installer":"installer","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}},"signatures":[],"reboot":"report","downgrade":"deny"})).unwrap();
    let binding = SoftwareExportBinding {
        target: "enterprise".into(),
        tenant_id: id,
        publication: [1; 32],
        target_digest: [2; 32],
        resource: "acme".into(),
        resource_version: "v1".into(),
        resource_digest: [3; 32],
        definition_digest: [4; 32],
        document_sha256: [5; 32],
        dependencies: vec![],
        artifacts: vec![SoftwareExportArtifact {
            url:
                "https://mdm.example/api/v1/software/native/sources/enterprise/artifacts/acme/v1/setup.msi"
                    .into(),
            length: 1024,
            sha256: [6; 32],
        }],
    };
    let mut step = SoftwareTaskStep {
        step_id: SoftwareStepDefinition {
            resource: "acme".into(),
            version: "v1".into(),
            variant: "default".into(),
            digest: [3; 32],
        }
        .step_id()
        .unwrap(),
        definition: SoftwareStepDefinition {
            resource: "acme".into(),
            version: "v1".into(),
            variant: "default".into(),
            digest: [3; 32],
        },
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
                "https://mdm.example/api/v1/software/native/sources/enterprise/exports/publication/"
                    .into(),
            identifier: "rss.publication".into(),
        },
    };
    step.export.validate_for(&step, id).unwrap();
    assert!(
        step.export
            .validate_for(&step, uuid::Uuid::new_v4())
            .is_err()
    );
    step.artifacts[0].sha256 = [7; 32];
    assert!(step.export.validate_for(&step, id).is_err());
    step.artifacts[0].sha256 = [6; 32];
    step.export = SoftwareTaskExport::Direct;
    assert!(step.export.validate_for(&step, id).is_err());
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
    let canonical: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-payload-v1.schema.json"
    ))
    .unwrap();
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
            step_id: SoftwareStepDefinition {
                resource: "acme".into(),
                version: "v1".into(),
                variant: "default".into(),
                digest: [3; 32],
            }
            .step_id()
            .unwrap(),
            definition: SoftwareStepDefinition {
                resource: "acme".into(),
                version: "v1".into(),
                variant: "default".into(),
                digest: [3; 32],
            },
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
            wire_version: 1,
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
            authorization: TaskAuthorization::Policy {
                policy_id: uuid::Uuid::new_v4(),
                policy_version: uuid::Uuid::new_v4(),
            },
            execution_context: SoftwareExecutionContext {
                revision: 1,
                os_version: [10, 0, 22621, 0],
                user_helper: true,
                system_broker: true,
                interactive_user: None,
                source_credentials: vec![],
                msix_sideload: false,
                msix_unsigned: false,
            },
            definition_digest: Sha256::digest(serde_json::to_vec(&steps).unwrap()).into(),
            steps,
            intent: SoftwareTaskIntent::Install,
        };
        assert_eq!(spec.validate().is_ok(), accepted);
    }
}
