use crate::applicability::*;

#[test]
fn macos_prerequisite_response_accepts_automatic_udid_without_widening_facts() {
    // UTM macOS 26.6.2 returns UDID alongside the three requested facts.
    let mut facts = plist::Dictionary::from_iter([
        ("OSVersion", plist::Value::from("26.6.2")),
        ("IsSupervised", true.into()),
        ("IsAppleSilicon", true.into()),
        ("UDID", "8A12E768-FE13-4F03-948B-AE5EE69E957B".into()),
    ]);
    let response = |facts: &plist::Dictionary| {
        plist::Dictionary::from_iter([("QueryResponses", plist::Value::from(facts.clone()))])
    };
    let context = Context::from_reports(&response(&facts), None, Channel::Device).unwrap();
    assert_eq!(context.version, Some(Version::parse("26.6.2").unwrap()));
    assert_eq!(context.supervised, Some(true));
    assert_eq!(context.apple_silicon, Some(true));
    assert_eq!(context.automated_enrollment, None);
    assert_eq!(context.user_approved, None);

    facts.insert("UnexpectedFact".into(), true.into());
    assert!(Context::from_reports(&response(&facts), None, Channel::Device).is_err());
    facts.remove("UnexpectedFact");
    facts.insert("OSVersion".into(), true.into());
    assert!(Context::from_reports(&response(&facts), None, Channel::Device).is_err());
}

fn device(version: &str) -> Context {
    Context {
        version: Some(Version::parse(version).unwrap()),
        channel: Channel::Device,
        enrollment: Enrollment::Device,
        supervised: Some(false),
        automated_enrollment: Some(false),
        user_approved: Some(true),
        apple_silicon: Some(true),
    }
}

#[test]
fn object_and_field_constraints_intersect_without_requiring_optional_evidence() {
    let object = Support::since("13.0").unwrap();
    assert_eq!(object.check(&device("15.0")), Ok(()));
    let field = Support::since("27.0").unwrap();
    assert_eq!(
        field.check(&device("26.0")),
        Err(Rejection::Unsupported(Condition::Version))
    );
    assert_eq!(field.check(&device("27.0")), Ok(()));
    let mut unknown = device("27.0");
    unknown.supervised = None;
    assert_eq!(field.check(&unknown), Ok(()));
}

#[test]
fn user_channel_and_user_enrollment_are_independent() {
    let support = Support {
        device_channel: false,
        enrollment: EnrollmentRule::DeviceOnly,
        ..Support::since("15.0").unwrap()
    };
    let mut target = device("15.0");
    assert_eq!(
        support.check(&target),
        Err(Rejection::Unsupported(Condition::Channel))
    );
    target.channel = Channel::User;
    assert_eq!(support.check(&target), Ok(()));
    target.enrollment = Enrollment::User;
    assert_eq!(
        support.check(&target),
        Err(Rejection::Unsupported(Condition::Enrollment))
    );
}

#[test]
fn missing_required_evidence_is_distinct_from_known_inapplicability() {
    let support = Support {
        supervised: true,
        automated_enrollment: true,
        ..Support::since("15.0").unwrap()
    };
    let mut target = device("15.0");
    target.supervised = None;
    assert_eq!(
        support.check(&target),
        Err(Rejection::MissingEvidence(Condition::Supervision))
    );
    target.supervised = Some(false);
    assert_eq!(
        support.check(&target),
        Err(Rejection::Unsupported(Condition::Supervision))
    );
    target.supervised = Some(true);
    target.automated_enrollment = Some(true);
    assert_eq!(support.check(&target), Ok(()));
}

#[test]
fn removed_beta_and_invalid_versions_cannot_be_admitted() {
    let removed = Support {
        removed: Some(Version::parse("26.0").unwrap()),
        ..Support::since("13.0").unwrap()
    };
    assert_eq!(
        removed.check(&device("26.0")),
        Err(Rejection::Unsupported(Condition::Version))
    );
    assert_eq!(removed.check(&device("15.0")), Ok(()));
    let beta = Support {
        beta: true,
        ..Support::since("27.0").unwrap()
    };
    assert_eq!(
        beta.check(&device("27.0")),
        Err(Rejection::Unsupported(Condition::Beta))
    );
    for invalid in ["", "15.-1", "15.0beta", "15.0.0.1", " 15", "15."] {
        assert!(Version::parse(invalid).is_err());
    }
    assert_eq!(
        Version::parse("15").unwrap(),
        Version::parse("15.0.0").unwrap()
    );
}
