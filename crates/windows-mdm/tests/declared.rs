use rss_mdm_windows_mdm::native::{
    AuthorizationTarget, Context, Enrollment, Request, Scope, Value, Verb,
    verification::{EffectFact, EffectState},
};

const ID: &str = "27fea311-68b9-4320-9fc4-296f6fdfafe2";
fn document() -> String {
    format!(
        r#"<DeclaredConfiguration schema="1.0" context="Device" id="{}" checksum="version-1" osdefinedscenario="MSFTExtensibilityMIProviderConfig"><DSC namespace="root/Microsoft/Windows/DesiredStateConfiguration" className="MSFT_FileDirectoryConfiguration"><Key name="DestinationPath">c:\data\file</Key><Value name="Contents">private contents</Value></DSC></DeclaredConfiguration>"#,
        ID
    )
}
fn request(operation: Verb) -> Request {
    Request::Node {
        node: "./Device/Vendor/MSFT/DeclaredConfiguration/Host/Complete/Documents/*/Document"
            .into(),
        instance: vec![ID.into()],
        operation,
        value: Some(Value::Xml(document())),
    }
}
fn context() -> Context {
    Context {
        build: Some([10, 0, 22631, 3958]),
        edition: Some(48),
        scope: Scope::Device,
        enrollment: Enrollment::LinkedCertificate,
    }
}
fn result(operation: &str, state: u32) -> String {
    document()
        .replace("DeclaredConfiguration", "DeclaredConfigurationResult")
        .replace(
            " checksum=",
            &format!(
                r#" result_checksum="result-1" operation="{operation}" state="{state}" checksum="#
            ),
        )
        .replace(
            "className=",
            &format!(r#"status="200" state="{state}" className="#),
        )
}
#[test]
fn mi_claims_are_class_wide_and_require_independent_authority() {
    let r = request(Verb::Replace);
    let resolved = r.resolve().unwrap();
    assert_eq!(resolved.objects().len(), 2);
    assert!(
        resolved
            .objects()
            .iter()
            .any(|o| o.kind() == "mi" && !o.key().contains("c:\\data"))
    );
    assert!(
        resolved
            .authorization()
            .iter()
            .any(|t| matches!(t, AuthorizationTarget::Mi { .. }))
    );
    assert!(
        r.compile(
            Context {
                enrollment: Enrollment::Primary,
                ..context()
            },
            1024
        )
        .is_err()
    );
    assert!(r.compile(context(), 1024).is_ok());
    let duplicate = document().replace(
        "</DeclaredConfiguration>",
        &format!(
            "{} </DeclaredConfiguration>",
            document()
                .split_once("<DSC")
                .unwrap()
                .1
                .split_once("</DSC>")
                .map(|(d, _)| format!("<DSC{d}</DSC>"))
                .unwrap()
        ),
    );
    assert!(rss_mdm_windows_mdm::native::declared::Document::parse(&duplicate).is_err());
}
#[test]
fn full_results_bind_version_resources_and_operation_including_delete() {
    for (verb, operation, state) in [(Verb::Replace, "Set", 60), (Verb::Delete, "Delete", 70)] {
        let r = request(verb);
        let effect = r.effect_plan(context()).unwrap();
        let query = effect
            .readback()
            .unwrap()
            .request
            .compile(context(), 2048)
            .unwrap();
        let uri = query.objects[0].key().to_owned();
        assert!(uri.contains("/Results/"));
        let fact = |value| EffectFact {
            uri: uri.clone(),
            status: Some(200),
            value: Some(value),
            receipt_accepted: true,
            result_accepted: true,
        };
        assert_eq!(
            effect.assess(&[fact(result(operation, state))]).state,
            EffectState::Verified
        );
        assert_eq!(
            effect
                .assess(&[fact(result(operation, state).replace("version-1", "stale"))])
                .state,
            EffectState::Diverged
        );
        assert_eq!(
            effect.assess(&[fact(result(operation, 20))]).state,
            EffectState::Diverged
        );
        assert_eq!(effect.assess(&[]).state, EffectState::Waiting);
        assert_eq!(
            effect
                .assess(&[EffectFact {
                    uri,
                    status: Some(404),
                    value: None,
                    receipt_accepted: true,
                    result_accepted: false
                }])
                .state,
            EffectState::Diverged
        );
    }
}
#[test]
fn guid_scope_and_unknown_servicing_branches_fail_closed() {
    let mut r = request(Verb::Replace);
    if let Request::Node { instance, .. } = &mut r {
        instance[0] = uuid::Uuid::new_v4().to_string();
    }
    assert!(r.resolve().is_err());
    assert!(
        request(Verb::Replace)
            .compile(
                Context {
                    build: Some([10, 0, 27000, 0]),
                    ..context()
                },
                1
            )
            .is_err()
    );
    assert!(
        request(Verb::Replace)
            .compile(
                Context {
                    build: Some([10, 0, 22631, 3957]),
                    ..context()
                },
                1
            )
            .is_err()
    );
}
