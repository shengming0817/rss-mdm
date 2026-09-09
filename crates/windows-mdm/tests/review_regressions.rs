use rss_mdm_windows_mdm::{CodecError as E, CodecLimits, CorrelationError as C, soap, syncml};
mod common;
const LOGIN: &str = include_str!("fixtures/initialization-login-status.xml");
#[test]
fn login_status_initialization_is_supported() {
    let l = CodecLimits::default();
    let message = syncml::decode(LOGIN.as_bytes(), &l).unwrap();
    assert_eq!(
        common::canonical(&syncml::encode(&message, &l).unwrap()),
        common::canonical(LOGIN.as_bytes())
    );
    for (wire, status) in [
        ("user", syncml::LoginStatus::User),
        ("others", syncml::LoginStatus::Others),
        ("none", syncml::LoginStatus::None),
    ] {
        for format in ["", "<Format xmlns=\"syncml:metinf\">chr</Format>"] {
            let xml = LOGIN
                .replace("<Data>user</Data>", &format!("<Data>{wire}</Data>"))
                .replace("</Meta>", &format!("{format}</Meta>"));
            let model = syncml::decode(xml.as_bytes(), &l).unwrap();
            assert_eq!(
                model.commands[0],
                syncml::Command::Alert {
                    id: 2,
                    alert: syncml::Alert::LoginStatus {
                        status,
                        explicit_format: !format.is_empty()
                    }
                }
            );
            assert_eq!(
                syncml::decode(&syncml::encode(&model, &l).unwrap(), &l).unwrap(),
                model
            );
            let reordered = xml
                .replace(
                    "<Type xmlns=\"syncml:metinf\">",
                    &format!("{format}<Type xmlns=\"syncml:metinf\">"),
                )
                .replace(&format!("{format}</Meta>"), "</Meta>");
            assert_eq!(syncml::decode(reordered.as_bytes(), &l).unwrap(), model);
        }
    }
}
#[test]
fn login_status_is_closed_and_bounded() {
    let l = CodecLimits::default();
    for bad in [
        LOGIN.replace("1224", "1226"),
        LOGIN.replace("<Data>user</Data>", "<Data>admin</Data>"),
        LOGIN.replace("MDM/LoginStatus", "MDM/AADUserToken"),
        LOGIN.replacen(
            "</Meta>",
            "<Format xmlns=\"syncml:metinf\">int</Format></Meta>",
            1,
        ),
        LOGIN.replacen(
            "</Meta>",
            "<Type xmlns=\"syncml:metinf\">com.microsoft/MDM/LoginStatus</Type></Meta>",
            1,
        ),
        LOGIN.replacen(
            "</Meta>",
            "</Meta><Source><LocURI>./bad</LocURI></Source>",
            1,
        ),
    ] {
        assert!(syncml::decode(bad.as_bytes(), &l).is_err());
    }
    let model = syncml::decode(LOGIN.as_bytes(), &l).unwrap();
    let limited = CodecLimits {
        items: 5,
        ..l.clone()
    };
    assert_eq!(
        syncml::decode(LOGIN.as_bytes(), &limited),
        Err(E::LimitExceeded)
    );
    assert_eq!(syncml::encode(&model, &limited), Err(E::LimitExceeded));
    let limited = CodecLimits {
        syncml_bytes: LOGIN.len() - 1,
        ..l
    };
    assert_eq!(
        syncml::decode(LOGIN.as_bytes(), &limited),
        Err(E::LimitExceeded)
    );
}
#[test]
fn forbidden_xml_has_distinct_classification() {
    let base = include_str!("fixtures/get.xml");
    let l = CodecLimits::default();
    for xml in [
        format!("<!DOCTYPE SyncML>{base}"),
        format!("<!DOCTYPE SyncML [<!ENTITY secret SYSTEM 'file:///never-read'>]>{base}"),
        format!("<?danger secret?>{base}"),
        base.replace("test-device", "&secret;"),
        base.replace("<SyncML ", "<SyncML attr=\"&secret;\" "),
        base.replace("SYNCML:SYNCML1.2", "&secret;"),
    ] {
        assert_eq!(syncml::decode(xml.as_bytes(), &l), Err(E::ForbiddenXml));
    }
    assert_eq!(
        syncml::decode(base.replace("DM/1.2", "DM/9.9").as_bytes(), &l),
        Err(E::Unsupported)
    );
    assert_eq!(
        syncml::decode(base.replace("test-device", "&#0;").as_bytes(), &l),
        Err(E::MalformedXml)
    );
    assert!(syncml::decode(base.replace("test-device", "a&amp;b&#32;c").as_bytes(), &l).is_ok());
}
#[test]
fn fault_uses_the_expected_response_path() {
    let l = CodecLimits::default();
    for (op, request_xml, response_xml) in [
        (
            soap::Operation::Discover,
            include_bytes!("fixtures/discovery-request.xml").as_slice(),
            include_bytes!("fixtures/discovery-response.xml").as_slice(),
        ),
        (
            soap::Operation::GetPolicies,
            include_bytes!("fixtures/policy-request.xml").as_slice(),
            include_bytes!("fixtures/policy-response.xml").as_slice(),
        ),
        (
            soap::Operation::Issue,
            include_bytes!("fixtures/issue-request.xml").as_slice(),
            include_bytes!("fixtures/issue-response.xml").as_slice(),
        ),
    ] {
        let request = soap::decode(request_xml, op, &l).unwrap();
        assert!(soap::decode_response(&request, response_xml, &l).is_ok());
        for fault in [
            include_bytes!("fixtures/fault-message-format.xml").as_slice(),
            include_bytes!("fixtures/fault-authentication.xml").as_slice(),
            include_bytes!("fixtures/fault-authorization.xml").as_slice(),
            include_bytes!("fixtures/fault-certificate-request.xml").as_slice(),
            include_bytes!("fixtures/fault-enrollment-server.xml").as_slice(),
        ] {
            let response = soap::decode_response(&request, fault, &l).unwrap();
            assert!(matches!(response.body, soap::Body::Fault(_)));
            let mut limited = l.clone();
            match op {
                soap::Operation::Discover => limited.discovery_bytes = fault.len() - 1,
                soap::Operation::GetPolicies => limited.xcep_bytes = fault.len() - 1,
                _ => limited.wstep_bytes = fault.len() - 1,
            }
            assert_eq!(
                soap::decode_response(&request, fault, &limited),
                Err(C::InvalidResponse(E::LimitExceeded))
            );
        }
        assert_eq!(
            soap::decode_response(&request, request_xml, &l),
            Err(C::InvalidResponse(E::UnexpectedOperation))
        );
    }
}
#[test]
fn correlation_preserves_remote_failure_source() {
    let l = CodecLimits::default();
    let mut request = soap::decode(
        include_bytes!("fixtures/discovery-request.xml"),
        soap::Operation::Discover,
        &l,
    )
    .unwrap();
    let mut response = soap::decode(
        include_bytes!("fixtures/discovery-response.xml"),
        soap::Operation::DiscoverResponse,
        &l,
    )
    .unwrap();
    response.header.relates_to = None;
    assert_eq!(
        soap::correlate(&request, &response, &l),
        Err(C::InvalidResponse(E::Structure))
    );
    request.header.message_id = None;
    assert_eq!(
        soap::correlate(&request, &response, &l),
        Err(C::InvalidRequest(E::Structure))
    );
    assert_eq!(
        soap::decode_response(&request, b"not XML", &l),
        Err(C::InvalidRequest(E::Structure))
    );
    request.header.message_id = Some("urn:uuid:test".into());
    response.header.relates_to = Some("urn:uuid:other".into());
    assert_eq!(soap::correlate(&request, &response, &l), Err(C::Mismatch));
    assert_eq!(
        soap::decode_response(&request, &soap::encode(&response, &l).unwrap(), &l),
        Err(C::Mismatch)
    );
}
