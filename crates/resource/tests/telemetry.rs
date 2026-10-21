use rss_mdm_resource::*;
fn spec() -> TelemetryProfileSpec {
    TelemetryProfileSpec {
        parameters: Default::default(),
        template: TelemetryTemplate {
            resource: "native.cpu".into(),
            version: "one".into(),
            variant: "x86_64".into(),
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
        },
        fields: vec![TelemetryFieldReference {
            key: "custom.load".into(),
            version: 1,
        }],
        projection: TelemetryProjection::Both,
        sample_millis: 10000,
        upload_millis: 60000,
        budget: TelemetryBudget {
            points: 64,
            bytes: 65536,
            resources: 4,
            execution_millis: 100,
            output_bytes: 4096,
        },
        boost: Some(TelemetryBoost {
            sample_millis: 1000,
            expires_at: 1000,
        }),
        backfill_seconds: 3600,
    }
}
#[test]
fn boost_expires_without_renewing_and_profile_roundtrips() {
    let value = TelemetryProfile::new(spec()).unwrap();
    assert_eq!(value.sample_millis(999), 1000);
    assert_eq!(value.sample_millis(1000), 10000);
    let restored: TelemetryProfile = serde_json::from_slice(&value.canonical()).unwrap();
    assert_eq!(restored, value);
    assert!(
        restored
            .validate_target(Platform::MacOS, Architecture::X86_64)
            .is_err()
    );
}
#[test]
fn reject_impossible_budget_duplicate_and_invalid_references() {
    let mut input = spec();
    input.budget.resources = 0;
    assert!(TelemetryProfile::new(input).is_err());
    let mut input = spec();
    input.fields.push(input.fields[0].clone());
    assert!(TelemetryProfile::new(input).is_err());
    let mut input = spec();
    input.fields[0].version = 0;
    assert!(TelemetryProfile::new(input.clone()).is_err());
    input.fields[0].version = 1;
    assert!(TelemetryProfile::new(input).is_ok());
    let mut input = spec();
    input.boost.as_mut().unwrap().sample_millis = 10;
    assert!(TelemetryProfile::new(input).is_err());
}
