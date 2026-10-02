use crate::{applicability::*, native::*};
use plist::{Dictionary, Value};

fn context() -> Context {
    Context {
        version: Some(Version::parse("26.0").unwrap()),
        channel: Channel::Device,
        enrollment: Enrollment::Device,
        supervised: Some(true),
        automated_enrollment: Some(true),
        user_approved: Some(true),
    }
}

#[test]
fn command_fields_are_native_typed_and_unknown_fields_cannot_pass() {
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &["AllowPasscodeRemovalAndLock"],
    };
    let mut fields = Dictionary::new();
    fields.insert("NotifyUser".into(), Value::Boolean(true));
    let command = Command::new("RestartDevice", fields.clone(), &target).unwrap();
    assert_eq!(command.request_type(), "RestartDevice");
    fields.insert("NotifyUser".into(), Value::String("true".into()));
    assert!(Command::new("RestartDevice", fields.clone(), &target).is_err());
    fields.insert("NotifyUser".into(), Value::Boolean(true));
    fields.insert(
        "RunScript".into(),
        Value::String("not an Apple command".into()),
    );
    assert!(Command::new("RestartDevice", fields, &target).is_err());
}

#[test]
fn required_right_and_channel_are_not_inferred_from_command_name() {
    let mut context = context();
    assert!(
        Command::new(
            "RestartDevice",
            Dictionary::new(),
            &Target {
                context: &context,
                access_rights: &[]
            }
        )
        .is_err()
    );
    context.channel = Channel::User;
    assert!(
        Command::new(
            "RestartDevice",
            Dictionary::new(),
            &Target {
                context: &context,
                access_rights: &["AllowPasscodeRemovalAndLock"]
            }
        )
        .is_err()
    );
}

#[test]
fn apple_application_manifest_does_not_inherit_ios_app_managed_support() {
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let mut fields = Dictionary::new();
    fields.insert(
        "AppComposedIdentifier".into(),
        Value::String("org.example.agent (ABCDEFGHIJ)".into()),
    );
    assert!(
        DeclarationPayload::new(
            "com.apple.configuration.app.managed",
            fields.clone(),
            &target
        )
        .is_ok()
    );
    fields.clear();
    fields.insert(
        "ManifestURL".into(),
        Value::String("https://example.test/app.plist".into()),
    );
    assert!(
        DeclarationPayload::new("com.apple.configuration.app.managed", fields, &target).is_err()
    );
}

#[test]
fn managed_application_requires_exactly_one_native_identity() {
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    assert!(
        DeclarationPayload::new(
            "com.apple.configuration.app.managed",
            Dictionary::new(),
            &target
        )
        .is_err()
    );
    let mut fields = Dictionary::new();
    fields.insert("AppStoreID".into(), Value::String("12345".into()));
    fields.insert("BundleID".into(), Value::String("org.example.app".into()));
    assert!(
        DeclarationPayload::new("com.apple.configuration.app.managed", fields, &target).is_err()
    );
}

#[test]
fn declared_assets_and_references_are_not_untyped_unknown_keys() {
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let mut fields = Dictionary::new();
    fields.insert(
        "StandardConfigurations".into(),
        Value::Array(vec![Value::String("configuration-one".into())]),
    );
    assert!(
        DeclarationPayload::new("com.apple.activation.simple", fields.clone(), &target).is_ok()
    );
    fields.insert(
        "StandardConfigurations".into(),
        Value::Array(vec![Value::Boolean(true)]),
    );
    assert!(DeclarationPayload::new("com.apple.activation.simple", fields, &target).is_err());
}

#[test]
fn historical_query_is_available_on_supported_old_os_but_not_after_removal() {
    let mut context = context();
    context.version = Some(Version::parse("15.0").unwrap());
    let mut fields = Dictionary::new();
    fields.insert(
        "Queries".into(),
        Value::Array(vec![Value::String("OSUpdateSettings".into())]),
    );
    let rights = &["AllowQueryDeviceInformation"];
    assert!(
        Command::new(
            "DeviceInformation",
            fields.clone(),
            &Target {
                context: &context,
                access_rights: rights
            }
        )
        .is_ok()
    );
    context.version = Some(Version::parse("27.0").unwrap());
    assert!(
        Command::new(
            "DeviceInformation",
            fields,
            &Target {
                context: &context,
                access_rights: rights
            }
        )
        .is_err()
    );
}

#[test]
fn later_documentation_does_not_raise_the_official_os_minimum() {
    let mut context = context();
    context.version = Some(Version::parse("15.0").unwrap());
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let mut fields = Dictionary::new();
    fields.insert(
        "CrossSiteTrackingPreventionRelaxedApps".into(),
        Value::Array(vec![Value::String("org.example.browser".into())]),
    );
    assert!(ProfilePayload::new("mdm/profiles/com.apple.domains.yaml", fields, &target).is_ok());
}

#[test]
fn documented_historical_response_fields_are_valid_on_their_real_os_versions() {
    let mut context = context();
    context.version = Some(Version::parse("15.0").unwrap());
    let target = Target {
        context: &context,
        access_rights: &["AllowQueryApplications"],
    };
    let command = Command::new("InstalledApplicationList", Dictionary::new(), &target).unwrap();
    let mut app = Dictionary::new();
    app.insert(
        "Path".into(),
        Value::String("/Applications/Example.app".into()),
    );
    let mut response = Dictionary::new();
    response.insert(
        "InstalledApplicationList".into(),
        Value::Array(vec![Value::Dictionary(app)]),
    );
    assert!(command.validate_response(&response, &target).is_ok());
}

#[test]
fn device_information_response_is_bound_to_requested_queries_and_real_rights() {
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &["AllowQueryDeviceInformation"],
    };
    let mut fields = Dictionary::new();
    fields.insert(
        "Queries".into(),
        Value::Array(vec![Value::String("OSVersion".into())]),
    );
    let command = Command::new("DeviceInformation", fields, &target).unwrap();
    let mut answers = Dictionary::new();
    answers.insert("OSVersion".into(), Value::String("26.0".into()));
    let response = |answers| {
        let mut fields = Dictionary::new();
        fields.insert("QueryResponses".into(), Value::Dictionary(answers));
        fields
    };
    assert!(
        command
            .validate_response(&response(answers.clone()), &target)
            .is_ok()
    );
    assert!(
        command
            .validate_response(
                &response(answers.clone()),
                &Target {
                    context: &context,
                    access_rights: &[]
                }
            )
            .is_err()
    );
    answers.insert("SerialNumber".into(), Value::String("unrequested".into()));
    assert!(
        command
            .validate_response(&response(answers), &target)
            .is_err()
    );
}

#[test]
fn application_commands_require_an_unambiguous_native_source() {
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &["AllowAppInstallation"],
    };
    for name in ["InstallApplication", "InstallEnterpriseApplication"] {
        assert!(Command::new(name, Dictionary::new(), &target).is_err());
        let mut fields = Dictionary::new();
        fields.insert(
            "ManifestURL".into(),
            Value::String("https://example.test/manifest.plist".into()),
        );
        assert!(Command::new(name, fields.clone(), &target).is_ok());
        fields.insert(
            "ManifestURL".into(),
            Value::String("http://example.test/manifest.plist".into()),
        );
        assert!(Command::new(name, fields, &target).is_err());
    }
    let mut fields = Dictionary::new();
    fields.insert("iTunesStoreID".into(), Value::Integer(1u64.into()));
    fields.insert("Identifier".into(), Value::String("org.example.app".into()));
    assert!(Command::new("InstallApplication", fields, &target).is_err());
}

#[test]
fn persistent_native_fields_preserve_plist_types_and_reject_authority_keys() {
    use crate::native::input::{CommandInput, FieldValue};
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &["AllowPasscodeRemovalAndLock"],
    };
    let input: CommandInput = serde_json::from_value(serde_json::json!({"requestType":"RestartDevice","fields":{"NotifyUser":{"type":"boolean","value":true}}})).unwrap();
    assert!(input.compile(&target).is_ok());
    let invalid =
        serde_json::json!({"requestType":"RestartDevice","fields":{},"userApproved":true});
    assert!(serde_json::from_value::<CommandInput>(invalid).is_err());
    let data: FieldValue =
        serde_json::from_value(serde_json::json!({"type":"data","value":"AQID"})).unwrap();
    assert_eq!(
        data.to_plist().unwrap().as_data(),
        Some([1, 2, 3].as_slice())
    );
    let date: FieldValue =
        serde_json::from_value(serde_json::json!({"type":"date","value":"2026-10-01T00:00:00Z"}))
            .unwrap();
    assert!(matches!(date.to_plist().unwrap(), Value::Date(_)));
}

#[test]
fn profile_composition_preserves_native_identity_scope_and_payload_versions() {
    use crate::native::{
        input::{FieldValue, Fields},
        profiles::{PayloadInput, ProfileInput},
    };
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let mut profile = ProfileInput {
        identifier: "org.example.profile".into(),
        uuid: uuid::Uuid::new_v4(),
        metadata: Fields::default(),
        payloads: vec![PayloadInput {
            schema: "mdm/profiles/com.apple.security.firewall.yaml".into(),
            identifier: "org.example.profile.firewall".into(),
            uuid: uuid::Uuid::new_v4(),
            metadata: Fields::default(),
            fields: Fields(std::collections::BTreeMap::from([(
                "EnableFirewall".into(),
                FieldValue::Boolean(true),
            )])),
        }],
    };
    let compiled = profile.compile(&target).unwrap();
    let body = crate::protocol::decode(&compiled.bytes).unwrap();
    assert_eq!(
        body.get("PayloadScope").and_then(Value::as_string),
        Some("System")
    );
    assert_eq!(
        body.get("PayloadVersion")
            .and_then(Value::as_unsigned_integer),
        Some(1)
    );
    assert_eq!(compiled.objects.len(), 2);
    profile.payloads.push(profile.payloads[0].clone());
    assert!(profile.compile(&target).is_err());
}

#[test]
fn ddm_tokens_bind_content_versions_and_activation_references() {
    use crate::native::{
        ddm::{DeclarationInput, DeclarationSet},
        input::{FieldValue, Fields},
    };
    use std::collections::BTreeMap;
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let input = DeclarationInput {
        identifier: "activation".into(),
        declaration_type: "com.apple.activation.simple".into(),
        payload: Fields(BTreeMap::from([(
            "StandardConfigurations".into(),
            FieldValue::Array(vec![FieldValue::String("missing-configuration".into())]),
        )])),
    };
    let first = input.compile("resource-version-1", &target).unwrap();
    let second = input.compile("resource-version-2", &target).unwrap();
    assert_ne!(first.server_token(), second.server_token());
    assert!(DeclarationSet::new("scope-generation", vec![first]).is_err());
    let empty = DeclarationSet::new("scope-generation", vec![]).unwrap();
    let manifest = empty.manifest();
    assert_eq!(manifest["Declarations"]["Assets"], serde_json::json!([]));
    assert_eq!(
        empty.tokens()["SyncTokens"]["DeclarationsToken"],
        manifest["DeclarationsToken"]
    );
}

#[test]
fn ddm_manifest_keeps_four_families_and_checks_asset_content_contracts() {
    use crate::native::{
        ddm::{DeclarationInput, DeclarationKind, DeclarationSet},
        input::{FieldValue as F, Fields},
    };
    use std::collections::BTreeMap;
    let mut context = context();
    context.version = Some(Version::parse("27.0").unwrap());
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let fields = |items: Vec<(&str, F)>| {
        Fields(
            items
                .into_iter()
                .map(|(k, v)| (k.into(), v))
                .collect::<BTreeMap<_, _>>(),
        )
    };
    let make = |id: &str, ty: &str, payload| {
        DeclarationInput {
            identifier: id.into(),
            declaration_type: ty.into(),
            payload,
        }
        .compile("version", &target)
        .unwrap()
    };
    let asset = |mime: &str| {
        make(
            "profile-data",
            "com.apple.asset.data",
            fields(vec![(
                "Reference",
                F::Dictionary(fields(vec![
                    (
                        "DataURL",
                        F::String("https://example.test/profile.mobileconfig".into()),
                    ),
                    ("ContentType", F::String(mime.into())),
                ])),
            )]),
        )
    };
    let configuration = || {
        make(
            "profile",
            "com.apple.configuration.legacy",
            fields(vec![(
                "ProfileAssetReference",
                F::String("profile-data".into()),
            )]),
        )
    };
    assert!(DeclarationSet::new("scope", vec![configuration(), asset("application/pdf")]).is_err());
    let activation = make(
        "activation",
        "com.apple.activation.simple",
        fields(vec![(
            "StandardConfigurations",
            F::Array(vec![F::String("profile".into())]),
        )]),
    );
    let management = make(
        "organization",
        "com.apple.management.organization-info",
        fields(vec![("Name", F::String("Example".into()))]),
    );
    let set = DeclarationSet::new(
        "scope",
        vec![
            configuration(),
            asset("application/plist"),
            activation,
            management,
        ],
    )
    .unwrap();
    let manifest = set.manifest();
    for family in ["Activations", "Configurations", "Assets", "Management"] {
        assert_eq!(
            manifest["Declarations"][family].as_array().unwrap().len(),
            1
        );
    }
    assert!(
        set.declaration(DeclarationKind::Configuration, "profile")
            .is_some()
    );
    assert!(set.declaration(DeclarationKind::Asset, "profile").is_none());
    assert!(
        set.declaration(DeclarationKind::Configuration, "removed")
            .is_none()
    );
}

#[test]
fn data_assets_require_https_and_consistent_size_hash() {
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let make = |url: &str, size: i64, hash: Option<&str>| {
        let mut reference = Dictionary::new();
        reference.insert("DataURL".into(), Value::String(url.into()));
        reference.insert("Size".into(), Value::Integer(size.into()));
        if let Some(hash) = hash {
            reference.insert("Hash-SHA-256".into(), Value::String(hash.into()));
        }
        let mut fields = Dictionary::new();
        fields.insert("Reference".into(), Value::Dictionary(reference));
        DeclarationPayload::new("com.apple.asset.data", fields, &target)
    };
    assert!(make("https://example.test/data", 0, None).is_ok());
    assert!(make("http://example.test/data", 1, None).is_err());
    assert!(make("https://example.test/data", -1, None).is_err());
    assert!(make("https://example.test/data", 0, Some(&"ab".repeat(32))).is_err());
}

#[test]
fn ddm_status_preserves_nested_identity_and_native_validity() {
    use crate::native::ddm::{StatusReport, Validity};
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let bytes = br#"{"FullReport":true,"StatusItems":{"management":{"declarations":{"activations":[],"configurations":[{"identifier":"profile","server-token":"old-token","active":true,"valid":"unknown"}],"assets":[],"management":[]}},"device":{"operating-system":{"version":"15.0"}}},"Errors":[]}"#;
    let report = StatusReport::decode(bytes, &target).unwrap();
    assert!(report.full_report());
    assert_eq!(report.items().len(), 2);
    let declarations = report.declarations().unwrap();
    assert_eq!(declarations.len(), 1);
    assert_eq!(declarations[0].validity, Validity::Unknown);
    assert!(declarations[0].active);
    assert_eq!(declarations[0].server_token, "old-token");
    assert!(
        StatusReport::decode(br#"{"StatusItems":{},"Errors":[],"Errors":[]}"#, &target).is_err()
    );
    assert!(
        StatusReport::decode(
            br#"{"StatusItems":{"device":{"unknown":"x"}},"Errors":[]}"#,
            &target
        )
        .is_err()
    );
}

#[test]
fn ddm_status_null_and_incremental_removal_are_not_missing_fields() {
    use crate::native::ddm::StatusReport;
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    assert!(
        StatusReport::decode(
            br#"{"StatusItems":{"device":{"operating-system":{"version":null}}},"Errors":[]}"#,
            &target
        )
        .is_ok()
    );
    assert!(StatusReport::decode(br#"{"StatusItems":{"security":{"certificate":{"list":[{"identifier":"removed","_removed":true}]}}},"Errors":[]}"#, &target).is_ok());
}

#[test]
fn ddm_full_delta_and_errors_preserve_native_evidence_semantics() {
    use crate::native::ddm::StatusReport;
    use serde_json::{Value as Json, json};
    use std::collections::BTreeMap;
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let report = |full, items: Json, errors: Json| {
        StatusReport::decode(
            &serde_json::to_vec(&json!({"FullReport":full,"StatusItems":items,"Errors":errors}))
                .unwrap(),
            &target,
        )
        .unwrap()
    };
    let cert = |name: &str| json!({"identifier":"certificate","subject-summary":name,"is-identity":false,"data":"AQID","future-extension":{"value":null}});
    let first = report(
        true,
        json!({"security":{"certificate":{"list":[cert("first")]}}}),
        json!([]),
    )
    .merge(&BTreeMap::new(), &target)
    .unwrap();
    assert_eq!(first["security.certificate.list"][0]["data"], "AQID");
    let mut updated = cert("second");
    updated.as_object_mut().unwrap().remove("future-extension");
    let next = report(
        false,
        json!({"security":{"certificate":{"list":[updated]}}}),
        json!([]),
    )
    .merge(&first, &target)
    .unwrap();
    assert!(
        next["security.certificate.list"][0]
            .get("future-extension")
            .is_none()
    );
    let removed = report(
        false,
        json!({"security":{"certificate":{"list":[{"identifier":"certificate","_removed":true}]}}}),
        json!([]),
    )
    .merge(&next, &target)
    .unwrap();
    assert_eq!(removed["security.certificate.list"], json!([]));
    assert!(
        report(true, json!({}), json!([]))
            .merge(&first, &target)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        report(false, json!({}), json!([]))
            .merge(&first, &target)
            .unwrap(),
        first
    );
    assert!(
        report(
            false,
            json!({}),
            json!([{"StatusItem":"security.certificate.list","Reasons":[{"Code":"unavailable"}]}])
        )
        .merge(&first, &target)
        .unwrap()
        .is_empty()
    );
    let bad = json!({"StatusItems":{"security":{"certificate":{"list":[{"identifier":"bad","subject-summary":"x","is-identity":false,"data":"not base64!"}]}}},"Errors":[]});
    assert!(StatusReport::decode(&serde_json::to_vec(&bad).unwrap(), &target).is_err());
}

#[test]
fn persistent_integer_values_do_not_depend_on_javascript_number_precision() {
    use crate::native::input::FieldValue;
    let value = FieldValue::Unsigned(u64::MAX);
    let encoded = serde_json::to_value(&value).unwrap();
    assert_eq!(encoded["value"], serde_json::json!("18446744073709551615"));
    let decoded: FieldValue = serde_json::from_value(encoded).unwrap();
    assert_eq!(
        decoded.to_plist().unwrap().as_unsigned_integer(),
        Some(u64::MAX)
    );
}

#[test]
fn plist_conversion_shares_one_budget_and_preserves_native_atoms() {
    use crate::native::input::Fields;
    let mut fields = plist::Dictionary::new();
    fields.insert("data".into(), plist::Value::Data(vec![0, 255, 128]));
    fields.insert("unsigned".into(), plist::Value::Integer(u64::MAX.into()));
    fields.insert(
        "nested".into(),
        plist::Value::Array(vec![
            plist::Value::Boolean(true),
            plist::Value::String("native".into()),
        ]),
    );
    assert_eq!(
        Fields::from_plist(&fields).unwrap().to_plist().unwrap(),
        fields
    );
    let mut deep = plist::Value::Boolean(true);
    for _ in 0..65 {
        deep = plist::Value::Array(vec![deep]);
    }
    fields.insert("deep".into(), deep);
    assert!(Fields::from_plist(&fields).is_err());
    let mut broad = plist::Dictionary::new();
    for name in ["a", "b"] {
        broad.insert(
            name.into(),
            plist::Value::Array(vec![plist::Value::Boolean(true); 33_000]),
        );
    }
    assert!(Fields::from_plist(&broad).is_err());
    let mut huge = plist::Dictionary::new();
    huge.insert(
        "data".into(),
        plist::Value::Data(vec![0; 12 * 1024 * 1024 + 1]),
    );
    assert!(Fields::from_plist(&huge).is_err());
    let mut invalid = plist::Dictionary::new();
    invalid.insert("real".into(), plist::Value::Real(f64::NAN));
    assert!(Fields::from_plist(&invalid).is_err());
}
