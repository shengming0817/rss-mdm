use rss_mdm_windows_mdm::{
    CodecLimits,
    soap::{self, Body, Operation},
};
const DISCOVER: &[u8] = include_bytes!("fixtures/discovery-request.xml");
#[test]
fn discovery_has_typed_body_and_no_authentication_result() {
    let m = soap::decode(DISCOVER, Operation::Discover, &CodecLimits::default()).unwrap();
    assert!(matches!(m.body, Body::Discover(_)));
    assert_eq!(m.header.message_id.as_deref(), Some("urn:uuid:test"));
}
#[test]
fn wrong_action_cannot_select_another_parser() {
    assert!(soap::decode(DISCOVER, Operation::GetPolicies, &CodecLimits::default()).is_err());
}
#[test]
fn attribute_is_escaped_once() {
    let l = CodecLimits::default();
    let message = soap::Message {
        header: soap::Header {
            message_id: None,
            relates_to: Some("urn:uuid:test".into()),
            to: None,
            reply_to: false,
            security: Some(soap::Security {
                username: None,
                timestamp: Some(soap::Timestamp {
                    id: "_0".into(),
                    created: "2026-09-08T00:00:00Z".into(),
                    expires: "2026-09-08T00:05:00Z".into(),
                }),
            }),
        },
        body: Body::IssueResponse(soap::IssueResponse {
            context: Some("a&b".into()),
            provisioning: rss_mdm_windows_mdm::Secret(vec![1]),
            request_id: None,
            disposition: None,
        }),
    };
    let bytes = soap::encode(&message, &l).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("Context=\"a&amp;b\""));
    assert_eq!(
        soap::decode(&bytes, Operation::IssueResponse, &l).unwrap(),
        message
    );
}
mod common;
#[test]
fn fixed_enrollment_samples_parse_and_encode_to_independent_goldens() {
    let l = CodecLimits::default();
    for (op, xml) in [
        (Operation::Discover, DISCOVER),
        (
            Operation::DiscoverResponse,
            include_bytes!("fixtures/discovery-response.xml").as_slice(),
        ),
        (
            Operation::GetPolicies,
            include_bytes!("fixtures/policy-request.xml").as_slice(),
        ),
        (
            Operation::GetPoliciesResponse,
            include_bytes!("fixtures/policy-response.xml").as_slice(),
        ),
        (
            Operation::Issue,
            include_bytes!("fixtures/issue-request.xml").as_slice(),
        ),
        (
            Operation::IssueResponse,
            include_bytes!("fixtures/issue-response.xml").as_slice(),
        ),
    ] {
        let m = soap::decode(xml, op, &l).unwrap_or_else(|e| panic!("{op:?}: {e}"));
        let encoded = soap::encode(&m, &l).unwrap();
        assert_eq!(
            common::canonical(&encoded),
            common::canonical(xml),
            "{op:?}"
        );
    }
}
#[test]
fn soap_response_requires_exact_request_correlation() {
    let l = CodecLimits::default();
    let request = soap::decode(DISCOVER, Operation::Discover, &l).unwrap();
    let mut response = soap::decode(
        include_bytes!("fixtures/discovery-response.xml"),
        Operation::DiscoverResponse,
        &l,
    )
    .unwrap();
    assert!(matches!(
        soap::correlate(&request, &response, &l).unwrap(),
        soap::CorrelatedResponse::Discovery(_)
    ));
    response.header.relates_to = Some("urn:uuid:other".into());
    assert!(soap::correlate(&request, &response, &l).is_err());
}
#[test]
fn secrets_are_redacted_and_faults_are_fixed() {
    let l = CodecLimits::default();
    let request = soap::decode(
        include_bytes!("fixtures/issue-request.xml"),
        Operation::Issue,
        &l,
    )
    .unwrap();
    let debug = format!("{request:?}");
    for secret in ["TEST-SECRET", "TEST-USER", "TEST-ID", "AQID"] {
        assert!(!debug.contains(secret));
    }
    for kind in [
        soap::FaultKind::MessageFormat,
        soap::FaultKind::Authentication,
        soap::FaultKind::Authorization,
        soap::FaultKind::CertificateRequest,
        soap::FaultKind::EnrollmentServer,
    ] {
        let m = soap::Message {
            header: soap::Header {
                message_id: None,
                relates_to: Some("urn:uuid:test".into()),
                to: None,
                reply_to: false,
                security: None,
            },
            body: Body::Fault(kind),
        };
        let bytes = soap::encode(&m, &l).unwrap();
        assert_eq!(soap::decode(&bytes, Operation::Fault, &l).unwrap(), m);
        assert!(!String::from_utf8_lossy(&bytes).contains("TEST-SECRET"));
        assert_eq!(
            soap::correlate(&request, &m, &l).unwrap(),
            soap::CorrelatedResponse::Fault(kind)
        );
    }
}
#[test]
fn soap_structure_namespace_and_duplicate_rejections() {
    let xml = String::from_utf8(DISCOVER.to_vec()).unwrap();
    let l = CodecLimits::default();
    for mutated in [
        xml.replace(
            "<a:MessageID>urn:uuid:test</a:MessageID>",
            "<a:MessageID>urn:uuid:test</a:MessageID><a:MessageID>second</a:MessageID>",
        ),
        xml.replace("<a:Action>", "<Action>")
            .replace("</a:Action>", "</Action>"),
        xml.replace("<RequestVersion>4.0</RequestVersion>", ""),
        xml.replace("</s:Body>", "<extra/></s:Body>"),
        xml.replace("<request>", "<request extra=\"1\">"),
        format!("{xml}<extra/>"),
    ] {
        assert!(soap::decode(mutated.as_bytes(), Operation::Discover, &l).is_err());
    }
}
#[test]
fn wstep_binary_budget_and_context_duplicates() {
    let xml = include_str!("fixtures/issue-request.xml");
    let l = CodecLimits {
        binary_bytes: 3,
        ..CodecLimits::default()
    };
    assert!(soap::decode(xml.as_bytes(), Operation::Issue, &l).is_ok());
    assert!(
        soap::decode(
            xml.as_bytes(),
            Operation::Issue,
            &CodecLimits {
                binary_bytes: 2,
                ..l.clone()
            }
        )
        .is_err()
    );
    for mutation in [
        xml.replace("AQID", "AQIDBA=="),
        xml.replace("AQID", "invalid!"),
        xml.replace("Name=\"OSVersion\"", "Name=\"OSEdition\""),
        xml.replace("#PKCS10", "#UNKNOWN"),
    ] {
        assert!(soap::decode(mutation.as_bytes(), Operation::Issue, &l).is_err());
    }
    let m = soap::decode(xml.as_bytes(), Operation::Issue, &l).unwrap();
    assert!(
        soap::encode(
            &m,
            &CodecLimits {
                binary_bytes: 2,
                ..l
            }
        )
        .is_err()
    );
}
#[test]
fn each_operation_has_exact_input_and_output_byte_boundaries() {
    let default = CodecLimits::default();
    for (op, xml) in [
        (Operation::Discover, DISCOVER),
        (
            Operation::GetPolicies,
            include_bytes!("fixtures/policy-request.xml").as_slice(),
        ),
        (
            Operation::Issue,
            include_bytes!("fixtures/issue-request.xml").as_slice(),
        ),
    ] {
        let set = |n| {
            let mut l = default.clone();
            match op {
                Operation::Discover => l.discovery_bytes = n,
                Operation::GetPolicies => l.xcep_bytes = n,
                _ => l.wstep_bytes = n,
            };
            l
        };
        assert!(soap::decode(xml, op, &set(xml.len())).is_ok());
        assert!(soap::decode(xml, op, &set(xml.len() - 1)).is_err());
        let m = soap::decode(xml, op, &default).unwrap();
        let encoded = soap::encode(&m, &default).unwrap();
        assert!(soap::encode(&m, &set(encoded.len())).is_ok());
        assert!(soap::encode(&m, &set(encoded.len() - 1)).is_err());
    }
}

#[test]
fn discovery_all_model_and_auth_policies_are_required() {
    let l = CodecLimits::default();
    let xml = std::str::from_utf8(DISCOVER).unwrap();
    let os = "<OSEdition>4</OSEdition>";
    let reordered = xml
        .replace(os, "")
        .replace("<RequestVersion>", &format!("{os}<RequestVersion>"));
    assert!(soap::decode(reordered.as_bytes(), Operation::Discover, &l).is_ok());
    for missing in [
        xml.replace(os, ""),
        xml.replace(
            "<AuthPolicies><AuthPolicy>OnPremise</AuthPolicy></AuthPolicies>",
            "",
        ),
        xml.replace("OnPremise", "Unknown"),
    ] {
        assert!(soap::decode(missing.as_bytes(), Operation::Discover, &l).is_err());
    }
    let offers = xml.replace(
        "<AuthPolicy>OnPremise</AuthPolicy>",
        "<AuthPolicy>Certificate</AuthPolicy><AuthPolicy>OnPremise</AuthPolicy>",
    );
    let m = soap::decode(offers.as_bytes(), Operation::Discover, &l).unwrap();
    let Body::Discover(d) = m.body else { panic!() };
    assert_eq!(d.auth_policies.len(), 2);
}
#[test]
fn wstep_multivalue_context_and_nullable_string_request_id() {
    let l = CodecLimits::default();
    let request = include_str!("fixtures/issue-request.xml");
    let request=request.replace("</c:AdditionalContext>","<c:ContextItem Name=\"IMEI\"><c:Value>111111111111111</c:Value></c:ContextItem><c:ContextItem Name=\"IMEI\"><c:Value>222222222222222</c:Value></c:ContextItem></c:AdditionalContext>");
    let m = soap::decode(request.as_bytes(), Operation::Issue, &l).unwrap();
    let Body::Issue(i) = m.body else { panic!() };
    assert_eq!(
        i.additional_context
            .0
            .iter()
            .filter(|(k, _)| k == "IMEI")
            .count(),
        2
    );
    let response = include_str!("fixtures/issue-response.xml");
    let id = "<RequestID xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">0</RequestID>";
    let string_id = "<RequestID xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">request-alpha</RequestID>";
    let moved = response.replace(id, "").replace(
        "<RequestSecurityTokenResponse>",
        &format!("<RequestSecurityTokenResponse>{string_id}"),
    );
    let model = soap::decode(moved.as_bytes(), Operation::IssueResponse, &l).unwrap();
    let Body::IssueResponse(i) = &model.body else {
        panic!()
    };
    assert_eq!(
        i.request_id,
        Some(soap::NillableText::Value(rss_mdm_windows_mdm::Secret(
            "request-alpha".into()
        )))
    );
    assert_eq!(
        soap::decode(
            &soap::encode(&model, &l).unwrap(),
            Operation::IssueResponse,
            &l
        )
        .unwrap(),
        model
    );
    let nil=response.replace(id,"<RequestID xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>");
    let model = soap::decode(nil.as_bytes(), Operation::IssueResponse, &l).unwrap();
    let Body::IssueResponse(i) = &model.body else {
        panic!()
    };
    assert_eq!(i.request_id, Some(soap::NillableText::Nil));
    assert_eq!(
        soap::decode(
            &soap::encode(&model, &l).unwrap(),
            Operation::IssueResponse,
            &l
        )
        .unwrap(),
        model
    );
}
#[test]
fn strict_username_and_response_timestamp() {
    let l = CodecLimits::default();
    let request = include_str!("fixtures/issue-request.xml")
        .replace("uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4", "other");
    assert!(soap::decode(request.as_bytes(), Operation::Issue, &l).is_ok());
    let mut model = soap::decode(
        include_bytes!("fixtures/issue-response.xml"),
        Operation::IssueResponse,
        &l,
    )
    .unwrap();
    model.header.security = None;
    assert!(soap::encode(&model, &l).is_err());
    let bad_date = include_str!("fixtures/issue-response.xml")
        .replace("2026-09-08T00:00:00.000Z", "invalid")
        .replace("2026-09-08T00:00:00Z", "invalid");
    assert!(soap::decode(bad_date.as_bytes(), Operation::IssueResponse, &l).is_err());
}
#[test]
fn normalized_attribute_budget_matches_writer() {
    let l = CodecLimits {
        field_bytes: 256,
        ..CodecLimits::default()
    };
    let mut model = soap::decode(
        include_bytes!("fixtures/issue-response.xml"),
        Operation::IssueResponse,
        &l,
    )
    .unwrap();
    let Body::IssueResponse(r) = &mut model.body else {
        panic!()
    };
    r.context = Some("&".repeat(100));
    let encoded = soap::encode(&model, &l).unwrap();
    assert_eq!(
        soap::decode(&encoded, Operation::IssueResponse, &l).unwrap(),
        model
    );
}
#[test]
fn all_soap_operation_byte_routes_and_fault_wire_goldens() {
    let l = CodecLimits::default();
    let cases = [
        (Operation::Discover, DISCOVER),
        (
            Operation::DiscoverResponse,
            include_bytes!("fixtures/discovery-response.xml").as_slice(),
        ),
        (
            Operation::GetPolicies,
            include_bytes!("fixtures/policy-request.xml").as_slice(),
        ),
        (
            Operation::GetPoliciesResponse,
            include_bytes!("fixtures/policy-response.xml").as_slice(),
        ),
        (
            Operation::Issue,
            include_bytes!("fixtures/issue-request.xml").as_slice(),
        ),
        (
            Operation::IssueResponse,
            include_bytes!("fixtures/issue-response.xml").as_slice(),
        ),
        (
            Operation::Fault,
            include_bytes!("fixtures/fault-message-format.xml").as_slice(),
        ),
    ];
    for (op, xml) in cases {
        let limits = |n| {
            let mut limits = l.clone();
            match op {
                Operation::Discover | Operation::DiscoverResponse | Operation::Fault => {
                    limits.discovery_bytes = n
                }
                Operation::GetPolicies | Operation::GetPoliciesResponse => limits.xcep_bytes = n,
                _ => limits.wstep_bytes = n,
            };
            limits
        };
        let model = soap::decode(xml, op, &limits(xml.len())).unwrap();
        assert!(soap::decode(xml, op, &limits(xml.len() - 1)).is_err());
        let output = soap::encode(&model, &l).unwrap();
        assert!(soap::encode(&model, &limits(output.len())).is_ok());
        assert!(soap::encode(&model, &limits(output.len() - 1)).is_err());
    }
    for (kind, xml) in [
        (
            soap::FaultKind::MessageFormat,
            include_bytes!("fixtures/fault-message-format.xml").as_slice(),
        ),
        (
            soap::FaultKind::Authentication,
            include_bytes!("fixtures/fault-authentication.xml").as_slice(),
        ),
        (
            soap::FaultKind::Authorization,
            include_bytes!("fixtures/fault-authorization.xml").as_slice(),
        ),
        (
            soap::FaultKind::CertificateRequest,
            include_bytes!("fixtures/fault-certificate-request.xml").as_slice(),
        ),
        (
            soap::FaultKind::EnrollmentServer,
            include_bytes!("fixtures/fault-enrollment-server.xml").as_slice(),
        ),
    ] {
        let model = soap::decode(xml, Operation::Fault, &l).unwrap();
        assert_eq!(model.body, Body::Fault(kind));
        assert_eq!(
            common::canonical(&soap::encode(&model, &l).unwrap()),
            common::canonical(xml)
        );
        let wire = std::str::from_utf8(xml).unwrap();
        let begin =
            wire.find("<s:Text xml:lang=\"en-US\">").unwrap() + "<s:Text xml:lang=\"en-US\">".len();
        let end = wire.find("</s:Text>").unwrap();
        let evil = format!("{}LEAK-ME&lt;&amp;{}", &wire[..begin], &wire[end..]);
        let parsed = soap::decode(evil.as_bytes(), Operation::Fault, &l).unwrap();
        assert!(!format!("{parsed:?}").contains("LEAK-ME"));
        assert_eq!(
            common::canonical(&soap::encode(&parsed, &l).unwrap()),
            common::canonical(xml)
        );
    }
}
#[test]
fn xcep_sha256_triple_does_not_inherit_historical_sha1() {
    let l = CodecLimits::default();
    let xml = include_str!("fixtures/policy-response.xml");
    for bad in [
        xml.replace("<group>1</group>", "<group>4</group>"),
        xml.replace("2.16.840.1.101.3.4.2.1", "1.3.14.3.2.29"),
        xml.replace("szOID_NIST_sha256", "szOID_OIWSEC_sha256RSASign"),
    ] {
        assert!(soap::decode(bad.as_bytes(), Operation::GetPoliciesResponse, &l).is_err());
    }
}
