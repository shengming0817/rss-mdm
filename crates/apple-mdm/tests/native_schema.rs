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
        apple_silicon: Some(true),
    }
}

#[test]
fn product_floor_rejects_native_objects_before_macos_15() {
    let mut context = context();
    context.version = Some(Version::parse("14.7").unwrap());
    assert!(
        Command::new(
            "InstalledApplicationList",
            Dictionary::new(),
            &Target {
                context: &context,
                access_rights: &["AllowQueryApplications"],
            }
        )
        .is_err()
    );
}

#[test]
fn prerequisite_reports_preserve_unknown_hardware_and_reject_extra_facts() {
    let mut facts = Dictionary::new();
    facts.insert("OSVersion".into(), "15.0".into());
    let mut report = Dictionary::new();
    report.insert("QueryResponses".into(), Value::Dictionary(facts.clone()));
    let context = Context::from_reports(&report, None, Channel::User).unwrap();
    assert_eq!(context.apple_silicon, None);
    assert_eq!(context.automated_enrollment, None);
    assert_eq!(context.channel, Channel::User);
    facts.insert("IsAppleSilicon".into(), "true".into());
    report.insert("QueryResponses".into(), Value::Dictionary(facts.clone()));
    assert!(Context::from_reports(&report, None, Channel::Device).is_err());
    facts.insert("IsAppleSilicon".into(), true.into());
    facts.insert("SerialNumber".into(), "unrequested".into());
    report.insert("QueryResponses".into(), Value::Dictionary(facts));
    assert!(Context::from_reports(&report, None, Channel::Device).is_err());
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
    let mut listed = body.clone();
    let report = |item: Dictionary| {
        crate::protocol::dictionary([("ProfileList", Value::Array(vec![item.into()]))])
    };
    assert!(profile.observed(&report(listed.clone())).unwrap());
    listed.remove("PayloadContent");
    assert!(profile.observed(&report(listed.clone())).is_err());
    listed = body.clone();
    listed.insert("IsEncrypted".into(), true.into());
    assert!(profile.observed(&report(listed)).is_err());
    listed = body.clone();
    let children = listed
        .get_mut("PayloadContent")
        .unwrap()
        .as_array_mut()
        .unwrap();
    children[0]
        .as_dictionary_mut()
        .unwrap()
        .remove("PayloadUUID");
    assert!(profile.observed(&report(listed)).is_err());
    listed = body.clone();
    let children = listed
        .get_mut("PayloadContent")
        .unwrap()
        .as_array_mut()
        .unwrap();
    children.push(children[0].clone());
    assert!(profile.observed(&report(listed)).is_err());
    listed = body.clone();
    let children = listed
        .get_mut("PayloadContent")
        .unwrap()
        .as_array_mut()
        .unwrap();
    children[0]
        .as_dictionary_mut()
        .unwrap()
        .insert("PayloadIdentifier".into(), "old-payload".into());
    assert!(!profile.observed(&report(listed)).unwrap());

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
fn ddm_incremental_claims_merge_disjoint_objects_and_preserve_unordered_removal() {
    use crate::native::{
        ddm::{DeclarationInput, DeclarationSet, ReportEvidence, project},
        input::{FieldValue as F, Fields},
    };
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let names = BTreeSet::from([
        "management.declarations".to_string(),
        "security.certificate.list".to_string(),
    ]);
    let input = DeclarationInput {
        identifier: "subscriptions".into(),
        declaration_type: "com.apple.configuration.management.status-subscriptions".into(),
        payload: Fields(BTreeMap::from([(
            "StatusItems".into(),
            F::Array(
                names
                    .iter()
                    .map(|name| {
                        F::Dictionary(Fields(BTreeMap::from([(
                            "Name".into(),
                            F::String(name.clone()),
                        )])))
                    })
                    .collect(),
            ),
        )])),
    };
    let declaration = input.compile("v1", &target).unwrap();
    let token = declaration.server_token().to_string();
    let set = DeclarationSet::new("scope", vec![declaration]).unwrap();
    let evidence = |full, items, errors| {
        ReportEvidence{
        context:context.clone(),report:serde_json::to_vec(&json!({"FullReport":full,"Errors":errors,"StatusItems":{
            "management":{"declarations":{"activations":[],"configurations":[{"identifier":"subscriptions","server-token":token,"active":true,"valid":"valid"}],"assets":[],"management":[]}},
            "security":{"certificate":{"list":items}}}})).unwrap(),subscriptions:names.clone(),declarations_token:set.tokens()["SyncTokens"]["DeclarationsToken"].as_str().unwrap().into()}
    };
    let cert =
        |id| json!({"identifier":id,"subject-summary":"fixture","is-identity":false,"data":"AQID"});
    let first = evidence(false, json!([cert("a")]), json!([]));
    let delta = evidence(false, json!([cert("b")]), json!([]));
    let mut streaming = crate::native::ddm::Projection::new(&set, &target).unwrap();
    streaming.observe(&first).unwrap();
    let checkpoint: crate::native::ddm::ProjectionState =
        serde_json::from_slice(&serde_json::to_vec(&streaming.checkpoint()).unwrap()).unwrap();
    let mut restored = crate::native::ddm::Projection::restore(&set, &target, checkpoint).unwrap();
    restored.observe(&delta).unwrap();
    assert_eq!(
        serde_json::to_value(restored.finish().unwrap()).unwrap(),
        serde_json::to_value(project(&set, &[first.clone(), delta.clone()], &target).unwrap())
            .unwrap()
    );
    let budget = evidence(
        false,
        json!([{"identifier":"large","subject-summary":"x".repeat(crate::native::ddm::PROJECTION_BYTES),"is-identity":false,"data":"AQID"}]),
        json!([]),
    );
    let mut bounded = crate::native::ddm::Projection::new(&set, &target).unwrap();
    bounded.observe(&budget).unwrap();
    assert!(
        serde_json::to_vec(&bounded.checkpoint()).unwrap().len()
            < crate::native::ddm::PROJECTION_BYTES
    );
    bounded.observe(&first).unwrap();
    let exhausted = bounded.finish().unwrap();
    assert!(!exhausted.synchronized);
    assert!(
        exhausted
            .unknown_items
            .contains("security.certificate.list")
    );
    let merged = project(&set, &[first.clone(), delta.clone()], &target).unwrap();
    assert_eq!(
        merged.items["security.certificate.list"],
        json!([cert("a"), cert("b")])
    );
    assert_eq!(merged.completeness, "unknown");
    let removed = evidence(
        false,
        json!([{"identifier":"a","_removed":true}]),
        json!([]),
    );
    let claims = vec![first.clone(), delta.clone(), removed.clone()];
    let projected = serde_json::to_value(project(&set, &claims, &target).unwrap()).unwrap();
    let reverse = serde_json::to_value(
        project(&set, &[removed, delta.clone(), first.clone()], &target).unwrap(),
    )
    .unwrap();
    assert_eq!(projected, reverse);
    assert_eq!(
        projected["items"]["security.certificate.list"],
        json!([cert("b")])
    );
    assert!(
        projected["unknownItems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "security.certificate.list")
    );
    let full = evidence(true, json!([cert("a")]), json!([]));
    let projected = project(&set, &[full, delta], &target).unwrap();
    assert!(
        projected
            .unknown_items
            .contains("security.certificate.list")
    );
    let failed = evidence(
        false,
        json!([]),
        json!([{"StatusItem":"security.certificate.list","Reasons":[{"Code":"unavailable"}]}]),
    );
    let projected = project(&set, &[first, failed], &target).unwrap();
    assert!(
        projected
            .unknown_items
            .contains("security.certificate.list")
    );
    assert_eq!(projected.errors.len(), 1);
    let bad = evidence(
        false,
        json!([{"identifier":"a","subject-summary":"x","is-identity":false,"data":"not base64!"}]),
        json!([]),
    );
    assert!(project(&set, &[bad], &target).is_err());
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

#[test]
fn every_frozen_command_has_a_behavior_owner() {
    for definition in generated::DEFINITIONS
        .iter()
        .filter(|d| d.kind == Kind::Command)
    {
        if definition.identity == "DeclarativeManagement" {
            assert_eq!(
                outcome::family(definition.identity),
                Err(Error::Unsupported)
            );
        } else {
            assert!(
                outcome::family(definition.identity).is_ok(),
                "{}",
                definition.identity
            );
        }
    }
    assert_eq!(
        Command::new(
            "RunScript",
            Dictionary::new(),
            &Target {
                context: &context(),
                access_rights: &[]
            }
        )
        .err(),
        Some(Error::Unsupported)
    );
}

#[test]
fn dynamic_application_dictionary_is_native_evidence_and_unknown_never_means_installed() {
    let ctx = context();
    let target = Target {
        context: &ctx,
        access_rights: &[
            "AllowQueryApplications",
            "QueryInstalledApps",
            "AllowAppInstallation",
        ],
    };
    let input = input::CommandInput {
        request_type: "ManagedApplicationList".into(),
        fields: Default::default(),
    };
    for (status, expected) in [
        ("Managed", outcome::Outcome::QueryResult),
        ("Unknown", outcome::Outcome::Unknown),
        ("UserRejected", outcome::Outcome::Rejected),
    ] {
        let response = crate::protocol::dictionary([(
            "ManagedApplicationList",
            Value::Dictionary(crate::protocol::dictionary([(
                "com.example.app",
                Value::Dictionary(crate::protocol::dictionary([
                    ("Status", status.into()),
                    ("ExternalVersionIdentifier", 1.into()),
                    ("HasConfiguration", false.into()),
                    ("ManagementFlags", 0.into()),
                ])),
            )])),
        )]);
        assert_eq!(
            outcome::interpret(
                &input,
                &response,
                crate::protocol::Status::Acknowledged,
                &target
            )
            .unwrap(),
            expected
        );
    }
    let response = crate::protocol::dictionary([(
        "ManagedApplicationList",
        Value::Dictionary(crate::protocol::dictionary([(
            "com.example.app",
            "invalid".into(),
        )])),
    )]);
    assert!(
        outcome::interpret(
            &input,
            &response,
            crate::protocol::Status::Acknowledged,
            &target
        )
        .is_err()
    );
}

#[test]
fn recovery_lock_requires_actual_hardware_and_update_deferrals_require_install_later() {
    let mut ctx = context();
    ctx.apple_silicon = None;
    let target = Target {
        context: &ctx,
        access_rights: &["AllowPasscodeRemovalAndLock"],
    };
    assert_eq!(
        Command::new(
            "SetRecoveryLock",
            crate::protocol::dictionary([("NewPassword", "secret".into())]),
            &target
        )
        .err(),
        Some(Error::Unsupported)
    );
    let updates = crate::protocol::dictionary([(
        "Updates",
        Value::Array(vec![Value::Dictionary(crate::protocol::dictionary([
            ("ProductKey", "update".into()),
            ("InstallAction", "InstallASAP".into()),
            ("MaxUserDeferrals", 1.into()),
        ]))]),
    )]);
    assert!(Command::new("ScheduleOSUpdate", updates, &target).is_err());
}

#[test]
fn profile_guards_require_terminal_and_complete_observation() {
    use profiles::{History, can_reserve};
    let id = uuid::Uuid::new_v4();
    let mut old = History {
        terminal: true,
        dispatched: true,
        observed: false,
        present: true,
        uuid: id,
    };
    assert!(!can_reserve(&[old], id, true));
    old = History {
        terminal: true,
        dispatched: true,
        observed: true,
        present: true,
        uuid: id,
    };
    assert!(can_reserve(&[old], id, false));
    assert!(!can_reserve(&[], id, false));
    assert!(can_reserve(&[], id, true));
}

#[test]
fn bootstrap_requires_known_ade_device_facts() {
    let mut context = context();
    assert!(crate::protocol::bootstrap_allowed(&context).is_ok());
    context.automated_enrollment = None;
    assert!(matches!(
        crate::protocol::bootstrap_allowed(&context),
        Err(crate::Error::Unsupported)
    ));
    context.automated_enrollment = Some(true);
    context.channel = Channel::User;
    assert!(matches!(
        crate::protocol::bootstrap_allowed(&context),
        Err(crate::Error::Unsupported)
    ));
}

#[test]
fn certificate_references_bind_scalar_and_array_values_to_this_profile() {
    use profiles::{PayloadInput, ProfileInput};
    let certificate = uuid::Uuid::new_v4();
    let make = |schema: &str, fields: Dictionary, id| PayloadInput {
        schema: schema.into(),
        identifier: format!("org.example.{id}"),
        uuid: id,
        metadata: input::Fields::default(),
        fields: input::Fields::from_plist(&fields).unwrap(),
    };
    let mut ctx = context();
    ctx.channel = Channel::User;
    let mut profile = ProfileInput {
        identifier: "org.example.refs".into(),
        uuid: uuid::Uuid::new_v4(),
        metadata: input::Fields::default(),
        payloads: vec![make(
            "mdm/profiles/com.apple.ews.account.yaml",
            crate::protocol::dictionary([(
                "AuthenticationCertificateUUID",
                certificate.to_string().into(),
            )]),
            uuid::Uuid::new_v4(),
        )],
    };
    let target = Target {
        context: &ctx,
        access_rights: &[],
    };
    assert!(profile.compile(&target).is_err());
    profile.payloads.push(make(
        "mdm/profiles/com.apple.security.pkcs12.yaml",
        crate::protocol::dictionary([("PayloadContent", Value::Data(vec![1, 2, 3]))]),
        certificate,
    ));
    assert!(profile.compile(&target).is_ok());
    profile.payloads[1].schema = "mdm/profiles/com.apple.security.root.yaml".into();
    assert!(
        profile.compile(&target).is_err(),
        "public certificate used as identity"
    );
    ctx.channel = Channel::Device;
    profile.payloads[0] = make(
        "mdm/profiles/com.apple.lom.yaml",
        crate::protocol::dictionary([(
            "DeviceCACertificateUUIDs",
            Value::Array(vec![certificate.to_string().into()]),
        )]),
        uuid::Uuid::new_v4(),
    );
    let target = Target {
        context: &ctx,
        access_rights: &[],
    };
    assert!(profile.compile(&target).is_ok());
    profile.payloads[1].schema = "mdm/profiles/com.apple.security.pkcs12.yaml".into();
    assert!(
        profile.compile(&target).is_err(),
        "identity used as CA anchor"
    );
    profile.payloads.pop();
    assert!(
        profile.compile(&target).is_err(),
        "array references external certificate"
    );
}

#[test]
fn lom_inner_failure_is_rejected_despite_outer_acknowledgement() {
    let ctx = context();
    let target = Target {
        context: &ctx,
        access_rights: &["DeviceLockAndRemovePasscode"],
    };
    let id = uuid::Uuid::new_v4().to_string();
    let command = input::CommandInput {
        request_type: "LOMDeviceRequest".into(),
        fields: input::Fields::from_plist(&crate::protocol::dictionary([(
            "RequestList",
            Value::Array(vec![Value::Dictionary(crate::protocol::dictionary([
                ("DeviceRequestType", "PowerON".into()),
                ("DeviceRequestUUID", id.clone().into()),
                ("DeviceDNSName", "device.example.test".into()),
                ("PrimaryIPv6AddressList", Value::Array(vec!["::1".into()])),
                ("SecondaryIPv6AddressList", Value::Array(vec![])),
                ("LOMProtocolVersion", 1.into()),
            ]))]),
        )]))
        .unwrap(),
    };
    for (success, expected) in [
        (true, outcome::Outcome::Acknowledged),
        (false, outcome::Outcome::Rejected),
    ] {
        let response = crate::protocol::dictionary([(
            "ResponseList",
            Value::Array(vec![Value::Dictionary(crate::protocol::dictionary([
                ("DeviceRequestUUID", id.clone().into()),
                ("DeviceRequestSuccess", success.into()),
            ]))]),
        )]);
        assert_eq!(
            outcome::interpret(
                &command,
                &response,
                crate::protocol::Status::Acknowledged,
                &target
            )
            .unwrap(),
            expected
        );
    }
}

#[test]
fn settings_dictionary_status_is_not_the_outer_acknowledgement() {
    use crate::protocol::{Status, dictionary};
    use outcome::Outcome;
    let ctx = context();
    let target = Target {
        context: &ctx,
        access_rights: &["AllowSettings"],
    };
    let command = input::CommandInput {
        request_type: "Settings".into(),
        fields: input::Fields::from_plist(&dictionary([(
            "Settings",
            Value::Array(vec![Value::Dictionary(dictionary([
                ("Item", "HostName".into()),
                ("HostName", "fixture.local".into()),
            ]))]),
        )]))
        .unwrap(),
    };
    for (status, expected) in [
        ("Error", Outcome::Rejected),
        ("Acknowledged", Outcome::Acknowledged),
        ("NotNow", Outcome::Deferred),
        ("CommandFormatError", Outcome::Rejected),
    ] {
        let response = dictionary([(
            "Settings",
            Value::Dictionary(dictionary([("Status", status.into())])),
        )]);
        assert_eq!(
            outcome::interpret(&command, &response, Status::Acknowledged, &target).unwrap(),
            expected
        );
    }
    assert_eq!(
        outcome::interpret(&command, &Dictionary::new(), Status::Acknowledged, &target).unwrap(),
        Outcome::Unknown
    );
}

#[test]
fn mixed_native_results_do_not_hide_failures_when_reordered() {
    use crate::protocol::{Status, dictionary};
    use outcome::Outcome;
    let ctx = context();
    let target = Target {
        context: &ctx,
        access_rights: &["AllowAppInstallation"],
    };
    let update = input::CommandInput {
        request_type: "ScheduleOSUpdate".into(),
        fields: input::Fields::from_plist(&dictionary([(
            "Updates",
            Value::Array(vec![Value::Dictionary(dictionary([
                ("ProductKey", "fixture".into()),
                ("InstallAction", "InstallLater".into()),
            ]))]),
        )]))
        .unwrap(),
    };
    let update_result = |action: &str, status: &str| {
        Value::Dictionary(dictionary([
            ("ProductKey", "fixture".into()),
            ("InstallAction", action.into()),
            ("Status", status.into()),
        ]))
    };
    for items in [
        vec![
            update_result("InstallLater", "Idle"),
            update_result("Error", "InstallFailed"),
        ],
        vec![
            update_result("Error", "InstallFailed"),
            update_result("InstallLater", "Idle"),
        ],
    ] {
        assert_eq!(
            outcome::interpret(
                &update,
                &dictionary([("UpdateResults", Value::Array(items))]),
                Status::Acknowledged,
                &target
            )
            .unwrap(),
            Outcome::Rejected
        );
    }
    let apps = input::CommandInput {
        request_type: "ManagedApplicationList".into(),
        fields: Default::default(),
    };
    for first in ["Unknown", "Installing"] {
        for statuses in [[first, "Failed"], ["Failed", first]] {
            let response = dictionary([(
                "ManagedApplicationList",
                Value::Dictionary(dictionary([
                    (
                        "org.example.first",
                        Value::Dictionary(dictionary([
                            ("Status", statuses[0].into()),
                            ("ExternalVersionIdentifier", 1.into()),
                            ("HasConfiguration", false.into()),
                            ("ManagementFlags", 0.into()),
                        ])),
                    ),
                    (
                        "org.example.second",
                        Value::Dictionary(dictionary([
                            ("Status", statuses[1].into()),
                            ("ExternalVersionIdentifier", 1.into()),
                            ("HasConfiguration", false.into()),
                            ("ManagementFlags", 0.into()),
                        ])),
                    ),
                ])),
            )]);
            assert_eq!(
                outcome::interpret(&apps, &response, Status::Acknowledged, &target).unwrap(),
                Outcome::Rejected
            );
        }
    }
    let query = input::CommandInput {
        request_type: "OSUpdateStatus".into(),
        fields: Default::default(),
    };
    let item = |status: &str| {
        Value::Dictionary(dictionary([
            ("ProductKey", "fixture".into()),
            ("IsDownloaded", true.into()),
            ("DownloadPercentComplete", Value::Real(1.0)),
            ("Status", status.into()),
        ]))
    };
    for items in [
        vec![item("Idle"), item("Failed")],
        vec![item("Failed"), item("Idle")],
    ] {
        assert_eq!(
            outcome::interpret(
                &query,
                &dictionary([("OSUpdateStatus", Value::Array(items))]),
                Status::Acknowledged,
                &target
            )
            .unwrap(),
            Outcome::Rejected
        );
    }
}

#[test]
fn ddm_projection_is_commutative_and_old_tokens_do_not_change_current_claims() {
    use crate::native::{
        ddm::{DeclarationInput, DeclarationSet, ReportEvidence, project},
        input::{FieldValue as F, Fields},
    };
    use std::collections::{BTreeMap, BTreeSet};
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let input = DeclarationInput {
        identifier: "subscriptions".into(),
        declaration_type: "com.apple.configuration.management.status-subscriptions".into(),
        payload: Fields(BTreeMap::from([(
            "StatusItems".into(),
            F::Array(vec![F::Dictionary(Fields(BTreeMap::from([(
                "Name".into(),
                F::String("device.operating-system.version".into()),
            )])))]),
        )])),
    };
    let declaration = input.compile("v1", &target).unwrap();
    let token = declaration.server_token().to_string();
    let set = DeclarationSet::new("scope", vec![declaration]).unwrap();
    let evidence = |token: &str, active: bool, version: &str| {
        ReportEvidence{context:context.clone(),report:serde_json::to_vec(&serde_json::json!({"FullReport":true,"Errors":[],"StatusItems":{"management":{"declarations":{"activations":[],"configurations":[{"identifier":"subscriptions","server-token":token,"active":active,"valid":"valid"}],"assets":[],"management":[]}},"device":{"operating-system":{"version":version}}}})).unwrap(),subscriptions:BTreeSet::from(["device.operating-system.version".into()]),declarations_token:set.tokens()["SyncTokens"]["DeclarationsToken"].as_str().unwrap().into()}
    };
    let first = evidence(&token, true, "26.0");
    let stale = evidence("older-token", false, "15.0");
    let stable = project(
        &set,
        &[first.clone(), stale.clone(), first.clone()],
        &target,
    )
    .unwrap();
    assert!(stable.synchronized);
    assert_eq!(stable.items["device.operating-system.version"], "26.0");
    let conflicting = evidence(&token, false, "26.1");
    let forward = serde_json::to_value(
        project(
            &set,
            &[first.clone(), stale.clone(), conflicting.clone()],
            &target,
        )
        .unwrap(),
    )
    .unwrap();
    let reverse =
        serde_json::to_value(project(&set, &[conflicting, stale, first], &target).unwrap())
            .unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(forward["synchronized"], false);
    assert_eq!(forward["declarations"][0]["native"]["valid"], "unknown");
    assert!(
        forward["items"]
            .get("device.operating-system.version")
            .is_none()
    );
    assert_eq!(forward["effect"], "unverified");
    assert_eq!(forward["compliance"], "unknown");
    let mut unknown = input.clone();
    unknown.payload = Fields(BTreeMap::from([(
        "StatusItems".into(),
        F::Array(vec![F::Dictionary(Fields(BTreeMap::from([(
            "Name".into(),
            F::String("invented.status".into()),
        )])))]),
    )]));
    assert!(unknown.compile("v1", &target).is_err());
}
#[test]
fn downloaded_asset_authority_and_legacy_structure_are_native_constraints() {
    use crate::native::{
        ddm::{AssetBinding, AssetInput, DeclarationInput, bind_assets},
        input::{FieldValue as F, Fields},
        profiles::{PayloadInput, ProfileInput, from_native, same_structure},
    };
    use std::collections::BTreeMap;
    let context = context();
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let input = DeclarationInput {
        identifier: "data".into(),
        declaration_type: "com.apple.asset.data".into(),
        payload: Fields::default(),
    };
    let binding = AssetBinding {
        selection: AssetInput {
            identifier: "data".into(),
            resource: "r".into(),
            version: "v1".into(),
            variant: "mac".into(),
            version_digest: [0xab; 32],
            content_type: "application/plist".into(),
            profile_schemas: vec![],
        },
        reference: "opaque".into(),
        length: 10,
        sha256: [1; 32],
        apple_silicon: true,
        profile: None,
    };
    let bound = bind_assets(
        &[input.clone()],
        &[binding.clone()],
        "https://mdm.test/native/assets/op",
        &target,
    )
    .unwrap();
    let document = bound[0].compile("v1", &target).unwrap().document();
    assert_eq!(
        document["Payload"]["Reference"]["DataURL"],
        "https://mdm.test/native/assets/op/data"
    );
    assert_eq!(document["Payload"]["Authentication"]["Type"], "MDM");
    assert!(bind_assets(&[input], &[binding], "http://mdm.test/", &target).is_err());
    let unbound = DeclarationInput {
        identifier: "data".into(),
        declaration_type: "com.apple.asset.data".into(),
        payload: Fields(BTreeMap::from([(
            "Reference".into(),
            F::Dictionary(Fields::default()),
        )])),
    };
    assert!(bind_assets(&[unbound], &[], "https://mdm.test/", &target).is_err());
    let profile = ProfileInput {
        identifier: "legacy".into(),
        uuid: uuid::Uuid::new_v4(),
        metadata: Fields::default(),
        payloads: vec![PayloadInput {
            schema: "mdm/profiles/com.apple.dock.yaml".into(),
            identifier: "legacy.dock".into(),
            uuid: uuid::Uuid::new_v4(),
            metadata: Fields::default(),
            fields: Fields::default(),
        }],
    };
    let compiled = profile.compile(&target).unwrap();
    let schemas = profile
        .payloads
        .iter()
        .map(|p| p.schema.clone())
        .collect::<Vec<_>>();
    let imported = from_native(&compiled.bytes, &schemas, Channel::Device)
        .unwrap()
        .compile(&target)
        .unwrap();
    assert!(same_structure(&compiled.objects, &imported.objects));
    assert!(from_native(&compiled.bytes, &schemas, Channel::User).is_err());
    let mut reordered = compiled.objects.clone();
    reordered.reverse();
    assert!(!same_structure(&compiled.objects, &reordered));
}
