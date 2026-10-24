use rss_mdm_windows_mdm::{
    CodecLimits,
    soap::{self, Operation},
};

#[test]
fn complete_microsoft_on_premise_requests_parse_without_rewriting_credentials() {
    for (operation, xml) in [
        (
            Operation::GetPolicies,
            include_str!("fixtures/policy-official-on-premise.xml"),
        ),
        (
            Operation::Issue,
            include_str!("fixtures/issue-official-on-premise.xml"),
        ),
    ] {
        let message = soap::decode(xml.as_bytes(), operation, &CodecLimits::default()).unwrap();
        let password = &message
            .header
            .security
            .unwrap()
            .username
            .unwrap()
            .password
            .0;
        assert!(password.starts_with("mypassword"));
        if operation == Operation::Issue {
            assert!(password.ends_with("\n                "));
        }
    }
}

#[test]
fn xcep_accepts_client_state_and_language_with_schema_validation() {
    // MS-XCEP Client permits a dateTime (including the initial year-one value)
    // and an xs:language; these are advisory, not enrollment credentials.
    let base = include_str!("fixtures/policy-request.xml");
    for date in [
        "0001-01-01T00:00:00",
        "2026-10-24T00:00:00Z",
        "2026-10-24T00:00:00.123+01:00",
    ] {
        let xml = base
            .replace(
                "<p:lastUpdate xsi:nil=\"true\"/>",
                &format!("<p:lastUpdate>{date}</p:lastUpdate>"),
            )
            .replace(
                "<p:preferredLanguage xsi:nil=\"true\"/>",
                "<p:preferredLanguage>en-US</p:preferredLanguage>",
            );
        assert!(
            soap::decode(
                xml.as_bytes(),
                Operation::GetPolicies,
                &CodecLimits::default()
            )
            .is_ok(),
            "{date}"
        );
    }
    let absent = base.replace("<p:lastUpdate xsi:nil=\"true\"/>", "");
    assert!(
        soap::decode(
            absent.as_bytes(),
            Operation::GetPolicies,
            &CodecLimits::default()
        )
        .is_ok()
    );
    for (field, value) in [
        ("lastUpdate", "2026-02-30T00:00:00Z"),
        ("lastUpdate", "tomorrow"),
        ("preferredLanguage", "en_US"),
        ("preferredLanguage", "en--US"),
    ] {
        let xml = base.replace(
            &format!("<p:{field} xsi:nil=\"true\"/>"),
            &format!("<p:{field}>{value}</p:{field}>"),
        );
        assert!(
            soap::decode(
                xml.as_bytes(),
                Operation::GetPolicies,
                &CodecLimits::default()
            )
            .is_err()
        );
    }
    let nil_with_content = base.replace(
        "<p:lastUpdate xsi:nil=\"true\"/>",
        "<p:lastUpdate xsi:nil=\"true\">2026-10-24T00:00:00Z</p:lastUpdate>",
    );
    assert!(
        soap::decode(
            nil_with_content.as_bytes(),
            Operation::GetPolicies,
            &CodecLimits::default()
        )
        .is_err()
    );
}

#[test]
fn windows_context_boolean_spellings_are_bounded() {
    let base = include_str!("fixtures/issue-request.xml");
    for name in ["TargetedUserLoggedIn", "UXInitiated", "NotInOobe"] {
        for value in [
            "True", "False", "true", "false", "0", "1", "trUe", "yes", "2",
        ] {
            let xml = base.replace("</c:AdditionalContext>", &format!("<c:ContextItem Name=\"{name}\"><c:Value>{value}</c:Value></c:ContextItem></c:AdditionalContext>"));
            let result = soap::decode(xml.as_bytes(), Operation::Issue, &CodecLimits::default());
            assert_eq!(
                result.is_ok(),
                !["trUe", "yes", "2"].contains(&value),
                "{name}={value}"
            );
        }
    }
}

#[test]
fn uri_whitespace_handling_does_not_normalize_passwords_or_allow_wrong_actions() {
    let base = include_str!("fixtures/policy-request.xml");
    let xml = base.replace("TEST-SECRET", " \tTEST-SECRET\n ");
    let message = soap::decode(
        xml.as_bytes(),
        Operation::GetPolicies,
        &CodecLimits::default(),
    )
    .unwrap();
    assert_eq!(
        message
            .header
            .security
            .unwrap()
            .username
            .unwrap()
            .password
            .0,
        " \tTEST-SECRET\n "
    );
    let wrong = base.replace("/IPolicy/GetPolicies", "/IPolicy/GetPoliciesEvil");
    assert!(
        soap::decode(
            wrong.as_bytes(),
            Operation::GetPolicies,
            &CodecLimits::default()
        )
        .is_err()
    );
}
