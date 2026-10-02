use rss_mdm_windows_mdm::native::{Context, Error, Operation, Scope, Value, Verb};

fn target(build: [u32; 4]) -> Context {
    Context {
        build: Some(build),
        edition: Some(48),
        scope: Scope::Device,
    }
}

#[test]
fn generated_ddf_controls_access_value_and_edition() {
    let path = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall";
    let context = target([10, 0, 22621, 1]);
    let op = Operation::compile(
        path,
        &[],
        Verb::Replace,
        Some(Value::Boolean(true)),
        context,
    )
    .unwrap();
    assert_eq!(op.uri(), path);
    assert!(matches!(
        op.command(7),
        rss_mdm_windows_mdm::syncml::Command::Replace { id: 7, .. }
    ));
    assert_eq!(
        Operation::compile(path, &[], Verb::Exec, None, context).err(),
        Some(Error::OperationNotAllowed)
    );
    assert_eq!(
        Operation::compile(
            path,
            &[],
            Verb::Replace,
            Some(Value::Text("true".into())),
            context
        )
        .err(),
        Some(Error::Value)
    );
    assert_eq!(
        Operation::compile(
            path,
            &[],
            Verb::Replace,
            Some(Value::Boolean(true)),
            Context {
                edition: Some(0),
                ..context
            }
        )
        .err(),
        Some(Error::Unsupported)
    );
}

#[test]
fn servicing_branches_do_not_become_a_single_minimum_build() {
    let path = "./Device/Vendor/MSFT/DMClient/Provider/*/ConfigRefresh/Enabled";
    for (build, allowed) in [
        ([10, 0, 22621, 1], false),
        ([10, 0, 22621, 3234], false),
        ([10, 0, 22621, 3235], true),
    ] {
        let result = Operation::compile(
            path,
            &["tenant & one".into()],
            Verb::Replace,
            Some(Value::Boolean(true)),
            target(build),
        );
        assert_eq!(result.is_ok(), allowed, "{build:?}");
        if let Ok(operation) = result {
            assert!(operation.uri().contains("/tenant%20%26%20one/"));
        }
    }
}

#[test]
fn native_identity_and_context_are_not_interchangeable() {
    let path = "./User/Vendor/MSFT/DMClient/Provider/*/FirstSyncStatus/IsSyncDone";
    let context = target([10, 0, 22621, 1]);
    assert_eq!(
        Operation::compile(path, &["provider".into()], Verb::Get, None, context).err(),
        Some(Error::Scope)
    );
    assert_eq!(
        Operation::compile(
            path,
            &[],
            Verb::Get,
            None,
            Context {
                scope: Scope::User,
                ..context
            }
        )
        .err(),
        Some(Error::Identity)
    );
    assert_eq!(
        Operation::compile(
            path,
            &["provider".into()],
            Verb::Get,
            None,
            Context {
                scope: Scope::User,
                build: None,
                ..context
            }
        )
        .err(),
        Some(Error::MissingEvidence)
    );
}

#[test]
fn official_xsd_checks_structure_and_rejects_external_resolution() {
    let path = "./Vendor/MSFT/SecureAssessment/Assessments";
    let context = target([10, 0, 22621, 521]);
    let valid = "<AssessmentsRoot><Assessments><Assessment><TestName>One</TestName><TestUri>https://example.test</TestUri></Assessment></Assessments></AssessmentsRoot>";
    assert!(
        Operation::compile(
            path,
            &[],
            Verb::Replace,
            Some(Value::Text(valid.into())),
            context
        )
        .is_ok()
    );
    for invalid in [
        valid.replace("<TestName>One</TestName>", ""),
        valid.replace("<TestName>One</TestName>", "<Unknown>One</Unknown>"),
        format!("<!DOCTYPE root SYSTEM 'file:///private/schema'>{valid}"),
    ] {
        assert_eq!(
            Operation::compile(
                path,
                &[],
                Verb::Replace,
                Some(Value::Text(invalid)),
                context
            )
            .err(),
            Some(Error::Value)
        );
    }
}

#[test]
fn admx_elements_use_native_types_and_complete_parameter_sets() {
    use rss_mdm_windows_mdm::native::admx::{Data, PolicyValue};
    use std::collections::BTreeMap;
    let path = "./Device/Vendor/MSFT/Policy/Config/AppVirtualization/StreamingAllowReestablishmentInterval";
    let context = Context {
        edition: Some(4),
        ..target([10, 0, 22621, 1])
    };
    let value = |number| {
        Value::Admx(PolicyValue {
            enabled: true,
            elements: BTreeMap::from([(
                "Streaming_Reestablishment_Interval_Prompt".into(),
                Data::Integer(number),
            )]),
        })
    };
    let op = Operation::compile(path, &[], Verb::Replace, Some(value(3600)), context).unwrap();
    let rss_mdm_windows_mdm::syncml::Command::Replace { items, .. } = op.command(1) else {
        panic!("native replace")
    };
    assert_eq!(
        items[0].data.as_ref().unwrap().0,
        "<enabled/><data id=\"Streaming_Reestablishment_Interval_Prompt\" value=\"3600\"/>"
    );
    assert_eq!(
        Operation::compile(path, &[], Verb::Replace, Some(value(3601)), context).err(),
        Some(Error::Value)
    );
    assert_eq!(
        Operation::compile(
            path,
            &[],
            Verb::Replace,
            Some(Value::Admx(PolicyValue {
                enabled: true,
                elements: BTreeMap::new()
            })),
            context
        )
        .err(),
        Some(Error::Value)
    );
}

#[test]
fn insider_metadata_cannot_become_stable_by_rewriting_the_version_number() {
    let path = "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/RemoveDefaultMicrosoftStorePackages";
    let context = Context {
        edition: Some(4),
        ..target([10, 0, 26200, 9999])
    };
    assert_eq!(
        Operation::compile(path, &[], Verb::Get, None, context).err(),
        Some(Error::Unsupported)
    );
    let supported = Operation::compile(
        "./Device/Vendor/MSFT/DMClient/Provider/*/ConfigRefresh/Enabled",
        &["provider".into()],
        Verb::Get,
        None,
        target([10, 0, 22621, 3235]),
    )
    .unwrap();
    assert_eq!(
        supported.applicability_source(),
        Some("39e38c079df4b447709c72aaf376ea1c174d18fa30fcc7dffb5213d7e5df49fa")
    );
}

#[test]
fn native_request_has_one_typed_shape_without_client_platform_evidence() {
    use rss_mdm_windows_mdm::native::Request;
    let body = serde_json::json!({"kind":"node","node":"./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall","instance":[],"operation":"replace","value":{"type":"boolean","value":true}});
    let request: Request = serde_json::from_value(body.clone()).unwrap();
    let compiled = request.compile(target([10, 0, 22621, 1]), 19).unwrap();
    assert_eq!(compiled.command.id(), 19);
    assert_eq!(compiled.objects.len(), 1);
    let mut invalid = body;
    invalid["osVersion"] = "10.0.22621.1".into();
    assert!(serde_json::from_value::<Request>(invalid).is_err());
    assert!(!format!("{request:?}").contains("Firewall"));
}

#[test]
fn mutation_readback_requires_native_results_instead_of_an_acknowledgement() {
    use rss_mdm_windows_mdm::native::{Context, Request, Scope, Value, Verb};
    let context = Context {
        build: Some([10, 0, 22621, 0]),
        edition: Some(48),
        scope: Scope::Device,
    };
    let request = Request::Node {
        node: "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana".into(),
        instance: vec![],
        operation: Verb::Replace,
        value: Some(Value::Integer(1)),
    };
    let verification = request.verification(context).unwrap().unwrap();
    let goal = verification.expected.values().next().unwrap();
    assert!(!goal.matches(Some(200), None));
    assert!(!goal.matches(Some(200), Some("0")));
    assert!(goal.matches(Some(200), Some("1")));
}

#[test]
fn native_presence_needs_results_and_read_recovery_excludes_every_mutating_verb() {
    use rss_mdm_windows_mdm::native::{Request, verification::Expected};
    assert!(!Expected::Present.matches(Some(200), None));
    assert!(Expected::Present.matches(Some(200), Some("")));
    for operation in [
        Verb::Get,
        Verb::Add,
        Verb::Replace,
        Verb::Delete,
        Verb::Exec,
    ] {
        let request = Request::Sequence {
            operations: vec![Request::Node {
                node: "./DevInfo/Mod".into(),
                instance: vec![],
                operation,
                value: None,
            }],
        };
        assert_eq!(request.read_only().unwrap(), operation == Verb::Get);
    }
}

#[test]
fn admx_templates_do_not_cross_unverified_windows_release_branches() {
    use rss_mdm_windows_mdm::native::admx::PolicyValue;
    use std::collections::BTreeMap;
    let path = "./Device/Vendor/MSFT/Policy/Config/AppVirtualization/StreamingAllowReestablishmentInterval";
    for (build, supported) in [
        (22621, true),
        (22631, true),
        (26100, true),
        (26200, true),
        (26300, true),
        (27000, false),
        (28000, false),
    ] {
        let value = Value::Admx(PolicyValue {
            enabled: false,
            elements: BTreeMap::new(),
        });
        let result = Operation::compile(
            path,
            &[],
            Verb::Replace,
            Some(value),
            Context {
                edition: Some(4),
                ..target([10, 0, build, 1])
            },
        );
        assert_eq!(
            result.is_ok(),
            supported,
            "unverified ADMX branch {build}: {:?}",
            result.err()
        );
    }
}

#[test]
fn learn_applicability_does_not_erase_an_explicit_ddf_servicing_branch() {
    let path = "./Vendor/MSFT/Firewall/MdmStore/Global/EnableAuditMode";
    for (build, supported) in [
        ([10, 0, 26100, 7018], false),
        ([10, 0, 26100, 7019], true),
        ([10, 0, 26200, 7018], false),
        ([10, 0, 26200, 7019], true),
    ] {
        let result = Operation::compile(path, &[], Verb::Get, None, target(build));
        assert_eq!(
            result.is_ok(),
            supported,
            "official DDF servicing branch {build:?}"
        );
    }
}
