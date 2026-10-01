use super::*;
use rss_mdm_compliance::Platform;
fn input() -> Input {
    Input{rule:Uuid::new_v4(),revision:1,definition:serde_json::from_value(json!({"name":"rule","severity":"high","enabled":true,"platform":"all","target":{"kind":"all"},"criteria":{"kind":"predicate","field":"custom.is_loaner","op":"eq","value":{"kind":"boolean","value":false}}})).unwrap(),watermark:1,evaluated_at:1,groups:vec![]}
}
#[test]
fn unknown_causes_and_absent_platform_are_not_compliance() {
    let mut input = input();
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let device = crate::assets::DeviceView {
        lists: Default::default(),
        device: "device".into(),
        channels: Default::default(),
        fields: Default::default(),
        quality: vec![],
        revisions: Default::default(),
    };
    let mut result = group::core::ObjectEvaluation {
        key: group::core::ObjectKey::new(tenant, "device").unwrap(),
        decision: group::core::Decision::Unknown,
        explanations: vec![],
        provenance: Default::default(),
    };
    for cause in [
        group::core::UnknownReason::Null,
        group::core::UnknownReason::Missing,
        group::core::UnknownReason::Deleted,
        group::core::UnknownReason::Unsupported,
        group::core::UnknownReason::Conflict,
    ] {
        result.explanations = vec![group::core::Explanation {
            path: vec![],
            outcome: group::core::Outcome::Unknown(cause),
        }];
        assert_eq!(
            assessment(&input, &device, result.clone(), vec![], vec![])
                .unwrap()
                .status,
            rss_mdm_compliance::Status::Unknown
        );
    }
    result.decision = group::core::Decision::Match;
    input.definition.platform = Platform::Windows;
    let source = |s: &str| SourceReference {
        source: s.into(),
        registration: "registration".into(),
        generation: "1".into(),
        epoch: "epoch".into(),
    };
    let value = assessment(&input, &device, result.clone(), vec![], vec![]).unwrap();
    assert_eq!(value.reason, rss_mdm_compliance::Reason::PlatformUnknown);
    let value = assessment(
        &input,
        &device,
        result.clone(),
        vec![],
        vec![source("mdm.apple")],
    )
    .unwrap();
    assert_eq!(
        value.reason,
        rss_mdm_compliance::Reason::PlatformNotApplicable
    );
    assert_eq!(value.applicability.sources[0].source, "mdm.apple");
    assert_eq!(
        assessment(&input, &device, result, vec![], vec![source("mdm.windows")])
            .unwrap()
            .status,
        rss_mdm_compliance::Status::Compliant
    );
}
#[test]
fn rules_have_no_timer_or_legacy_field_surface() {
    let definition = serde_json::to_value(input().definition).unwrap();
    for key in ["graceSeconds", "ttl", "expiresAt", "validUntil"] {
        let mut value = definition.clone();
        value[key] = json!(1);
        assert!(serde_json::from_value::<Definition>(value).is_err());
    }
    let mut value = definition;
    value["criteria"]["value"] = json!({"kind":"string","value":"false"});
    let rule: Definition = serde_json::from_value(value).unwrap();
    assert!(
        validate_definition(
            &rule,
            TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            Uuid::new_v4(),
            &rss_mdm_inventory::Catalog::new(rss_mdm_inventory::builtin::fields()).unwrap(),
        )
        .is_err()
    );
}
