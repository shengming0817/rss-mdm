use rss_mdm_windows_mdm::{
    CodecLimits,
    soap::{self, Operation},
};

#[test]
fn wstep_extensions_are_bounded_and_cannot_replace_required_claims() {
    // MS-WSTEP 3.1.4.1.3.3/.4 use wildcard content and foreign attributes.
    let limits = CodecLimits::default();
    for (operation, base, prefix, tag) in [
        (
            Operation::Issue,
            include_str!("fixtures/issue-request.xml"),
            "t:",
            "RequestSecurityToken",
        ),
        (
            Operation::IssueResponse,
            include_str!("fixtures/issue-response.xml"),
            "",
            "RequestSecurityTokenResponse",
        ),
    ] {
        let opening = format!("<{prefix}{tag}>");
        let closing = format!("</{prefix}{tag}>");
        assert!(base.contains(&opening) && base.contains(&closing));
        let extended = base.replace(
            &closing,
            &format!("<v:Hint xmlns:v=\"urn:example:vendor\"><v:Value>ignored</v:Value></v:Hint>{closing}"),
        );
        assert_ne!(extended, base);
        assert_eq!(
            soap::decode(extended.as_bytes(), operation, &limits).unwrap(),
            soap::decode(base.as_bytes(), operation, &limits).unwrap()
        );
        let attribute = base.replace(
            &opening,
            &format!("<{prefix}{tag} xmlns:v=\"urn:example:vendor\" v:hint=\"ignored\">"),
        );
        assert_ne!(attribute, base);
        assert!(soap::decode(attribute.as_bytes(), operation, &limits).is_ok());
        let unqualified = base.replace(&opening, &format!("<{prefix}{tag} hint=\"invalid\">"));
        assert!(soap::decode(unqualified.as_bytes(), operation, &limits).is_err());
        let deep = base.replace(
            &closing,
            &format!(
                "{}{}{closing}",
                "<v:x xmlns:v=\"urn:example:vendor\">".repeat(40),
                "</v:x>".repeat(40)
            ),
        );
        assert!(soap::decode(deep.as_bytes(), operation, &limits).is_err());
        let entity = extended.replace("ignored", "&external;");
        assert!(soap::decode(entity.as_bytes(), operation, &limits).is_err());
    }
    let base = include_str!("fixtures/issue-request.xml");
    let metadata =
        "<c:ContextItem Name=\"urn:example:metadata\"><c:Value>untrusted</c:Value></c:ContextItem>";
    let extended = base.replace(
        "</c:AdditionalContext>",
        &format!("{metadata}</c:AdditionalContext>"),
    );
    let message = soap::decode(extended.as_bytes(), Operation::Issue, &limits).unwrap();
    let soap::Body::Issue(issue) = message.body else {
        panic!()
    };
    assert!(
        issue
            .additional_context
            .0
            .iter()
            .any(|(k, v)| k == "urn:example:metadata" && v == "untrusted")
    );
    let missing = extended.replace("Name=\"DeviceID\"", "Name=\"OtherDeviceID\"");
    assert!(soap::decode(missing.as_bytes(), Operation::Issue, &limits).is_err());
    let nested_required = extended
        .replace(
            "<t:TokenType>",
            "<v:Hint xmlns:v=\"urn:example:vendor\"><t:TokenType>",
        )
        .replace("</t:TokenType>", "</t:TokenType></v:Hint>");
    assert!(soap::decode(nested_required.as_bytes(), Operation::Issue, &limits).is_err());
    let outside = base.replace(
        "</s:Body>",
        "<v:Hint xmlns:v=\"urn:example:vendor\"/></s:Body>",
    );
    assert!(soap::decode(outside.as_bytes(), Operation::Issue, &limits).is_err());
    let duplicate = extended.replace(
        "</c:AdditionalContext>",
        &format!("{metadata}</c:AdditionalContext>"),
    );
    assert!(soap::decode(duplicate.as_bytes(), Operation::Issue, &limits).is_err());
    let budget = CodecLimits { items: 1, ..limits };
    assert!(soap::decode(extended.as_bytes(), Operation::Issue, &budget).is_err());
}

#[test]
fn enrollment_fault_subcodes_use_the_mde2_soap_namespace() {
    // MS-MDE2 2.2.10 assigns all five enrollment subcodes to s:, not
    // the discovery namespace. Assert the wire QName independently of round-trip.
    let limits = CodecLimits::default();
    for (name, fixture) in [
        (
            "MessageFormat",
            include_str!("fixtures/fault-message-format.xml"),
        ),
        (
            "Authentication",
            include_str!("fixtures/fault-authentication.xml"),
        ),
        (
            "Authorization",
            include_str!("fixtures/fault-authorization.xml"),
        ),
        (
            "CertificateRequest",
            include_str!("fixtures/fault-certificate-request.xml"),
        ),
        (
            "EnrollmentServer",
            include_str!("fixtures/fault-enrollment-server.xml"),
        ),
    ] {
        let expected = fixture.replace(&format!("e:{name}"), &format!("s:{name}"));
        let message = soap::decode(expected.as_bytes(), Operation::Fault, &limits).unwrap();
        // Microsoft's Authorization example uses Receiver; both SOAP error
        // classes are legal and the product retains only the enrollment category.
        let receiver = expected.replace("s:Sender", "s:Receiver");
        assert_eq!(
            soap::decode(receiver.as_bytes(), Operation::Fault, &limits)
                .unwrap()
                .body,
            message.body
        );
        let encoded = String::from_utf8(soap::encode(&message, &limits).unwrap()).unwrap();
        assert!(encoded.contains(&format!("<s:Subcode><s:Value>s:{name}</s:Value>")));
        let wrong_namespace = expected.replace(&format!("s:{name}"), &format!("e:{name}"));
        assert!(soap::decode(wrong_namespace.as_bytes(), Operation::Fault, &limits).is_err());
    }
}

#[test]
fn native_windows_policy_allows_bounded_client_extensions_only() {
    // MS-XCEP Client ends with xs:any namespace=##any processContents=lax.
    let xml = include_str!("fixtures/policy-native-windows11.xml");
    let limits = CodecLimits::default();
    let message = soap::decode(xml.as_bytes(), Operation::GetPolicies, &limits).unwrap();
    assert!(matches!(message.body, soap::Body::GetPolicies));
    assert_eq!(
        message
            .header
            .security
            .unwrap()
            .username
            .unwrap()
            .username
            .0,
        "TEST-USER"
    );
    let extension = "<ns4:TPMManufacturer>IBM</ns4:TPMManufacturer>";
    let vendor = xml.replace(
        extension,
        "<v:hint xmlns:v=\"urn:example:vendor\"><v:nested>ignored</v:nested></v:hint>",
    );
    assert!(soap::decode(vendor.as_bytes(), Operation::GetPolicies, &limits).is_ok());
    let duplicate = xml.replace(extension, "<ns4:lastUpdate xsi:nil=\"true\"/>");
    assert!(soap::decode(duplicate.as_bytes(), Operation::GetPolicies, &limits).is_err());
    let outside = xml
        .replace(extension, "")
        .replace("</ns4:client>", &format!("</ns4:client>{extension}"));
    assert!(soap::decode(outside.as_bytes(), Operation::GetPolicies, &limits).is_err());
    let deep = xml.replace(
        extension,
        &format!(
            "{}{}",
            "<v:hint xmlns:v=\"urn:example:vendor\">".repeat(40),
            "</v:hint>".repeat(40)
        ),
    );
    assert!(soap::decode(deep.as_bytes(), Operation::GetPolicies, &limits).is_err());
    let entity = xml.replace(
        extension,
        "<ns4:TPMManufacturer>&external;</ns4:TPMManufacturer>",
    );
    assert!(soap::decode(entity.as_bytes(), Operation::GetPolicies, &limits).is_err());
    let budget = CodecLimits { items: 1, ..limits };
    assert!(soap::decode(xml.as_bytes(), Operation::GetPolicies, &budget).is_err());
}

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
