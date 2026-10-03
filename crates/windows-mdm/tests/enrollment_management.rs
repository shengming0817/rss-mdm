use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    provisioning::{self, EnrollmentType, Provisioning},
    syncml::{self, Challenge, Command},
};

#[test]
fn status_uses_one_documented_grammar_and_preserves_authentication() {
    let limits = CodecLimits::default();
    let mut message =
        syncml::decode(include_bytes!("fixtures/status-details.xml"), &limits).unwrap();
    let Command::Status(s) = &mut message.commands[0] else {
        panic!()
    };
    s.source_refs = vec!["device".into()];
    s.challenge = Some(Challenge {
        media_type: "syncml:auth-md5".into(),
        nonce: Some(Secret(STANDARD.encode([3u8; 16]))),
    });
    s.credential = Some(syncml::Credential {
        meta: syncml::Meta {
            format: Some("b64".into()),
            media_type: Some("syncml:auth-basic".into()),
            ..Default::default()
        },
        data: Secret("dTpw".into()),
    });
    let bytes = syncml::encode(&message, &limits).unwrap();
    assert_eq!(syncml::decode(&bytes, &limits).unwrap(), message);
    let xml = String::from_utf8(bytes).unwrap();
    assert!(xml.find("<SourceRef>").unwrap() < xml.find("<Cred>").unwrap());
    assert!(xml.find("<Cred>").unwrap() < xml.find("<Chal>").unwrap());
    let mixed = xml.replace("</Status>", "<SourceRef>mixed</SourceRef></Status>");
    assert!(syncml::decode(mixed.as_bytes(), &limits).is_err());
}

#[test]
fn provisioning_selects_enrollment_store_and_escapes_the_subject() {
    let poll = rss_mdm_windows_mdm::provisioning::Poll {
        interval_for_first_set_of_retries: 15,
        number_of_first_retries: 10,
        interval_for_second_set_of_retries: 0,
        number_of_second_retries: 0,
        interval_for_remaining_scheduled_retries: 1440,
        number_of_remaining_scheduled_retries: 0,
        poll_on_login: false,
        all_users_poll_on_first_login: false,
    };
    let mut p = Provisioning {
        push_pfn: None,
        poll: &poll,
        enrollment_type: EnrollmentType::Full,
        enterprise_device_id: "enterprise-device-id",
        issuer: &[1, 2],
        certificate: &[3, 4],
        issuer_thumbprint: "1111111111111111111111111111111111111111",
        certificate_thumbprint: "2222222222222222222222222222222222222222",
        certificate_subject: "CN=device,O=RSS",
        management_url: "https://mdm.example.test/ManagementServer/MDM.svc",
        provider_id: "RSS-MDM",
        username: "protocol-account",
        client_password: Secret("device-secret"),
        server_password: Secret("server-secret"),
        server_nonce: &[0u8; 32],
    };
    let full =
        String::from_utf8(provisioning::encode(&p, &CodecLimits::default()).unwrap()).unwrap();
    assert!(full.contains("Subject=CN%3Ddevice%2CO%3DRSS&amp;Stores=My%5CUser"));
    assert!(full.contains("name=\"ROLE\" value=\"32\""));
    assert!(full.contains("name=\"EntDMID\" value=\"enterprise-device-id\""));
    assert!(full.contains("type=\"My\"><characteristic type=\"User\""));
    p.enrollment_type = EnrollmentType::Device;
    let device =
        String::from_utf8(provisioning::encode(&p, &CodecLimits::default()).unwrap()).unwrap();
    assert!(device.contains("type=\"My\"><characteristic type=\"System\""));
    assert!(!device.contains("SSLCLIENTCERTSEARCHCRITERIA"));
    p.server_nonce = &[0u8; 1];
    assert!(provisioning::encode(&p, &CodecLimits::default()).is_err());
}

#[test]
fn current_windows_discovery_and_optional_context_remain_standard_inputs() {
    use rss_mdm_windows_mdm::soap::{self, Body, Operation};
    let limits = CodecLimits::default();
    for version in ["4.0", "5.0", "6.0", "7.0"] {
        let xml = String::from_utf8(include_bytes!("fixtures/discovery-request.xml").to_vec())
            .unwrap()
            .replace(
                "<RequestVersion>4.0</RequestVersion>",
                &format!("<RequestVersion>{version}</RequestVersion>"),
            );
        assert!(soap::decode(xml.as_bytes(), Operation::Discover, &limits).is_ok());
    }
    let mut issue = soap::decode(
        include_bytes!("fixtures/issue-request.xml"),
        Operation::Issue,
        &limits,
    )
    .unwrap();
    let Body::Issue(input) = &mut issue.body else {
        panic!()
    };
    input.additional_context.0.extend([
        ("UXInitiated".into(), "true".into()),
        ("NotInOobe".into(), "true".into()),
        ("DomainName".into(), "example.test".into()),
        ("ExternalMgmtAgentHint".into(), "hint".into()),
    ]);
    let encoded = soap::encode(&issue, &limits).unwrap();
    assert_eq!(
        soap::decode(&encoded, Operation::Issue, &limits).unwrap(),
        issue
    );
}

#[test]
fn native_poll_requires_explicit_reachable_schedule_and_complete_typed_maintenance() {
    use rss_mdm_windows_mdm::{native::Request, provisioning::Poll};
    let poll = Poll {
        interval_for_first_set_of_retries: 15,
        number_of_first_retries: 10,
        interval_for_second_set_of_retries: 0,
        number_of_second_retries: 0,
        interval_for_remaining_scheduled_retries: 1440,
        number_of_remaining_scheduled_retries: 0,
        poll_on_login: false,
        all_users_poll_on_first_login: false,
    };
    assert!(poll.validate().is_ok());
    let json = serde_json::to_value(&poll).unwrap();
    let mut missing = json.as_object().unwrap().clone();
    missing.remove("poll_on_login");
    assert!(serde_json::from_value::<Poll>(serde_json::Value::Object(missing)).is_err());
    let mut finite = poll.clone();
    finite.number_of_remaining_scheduled_retries = 1;
    assert!(finite.validate().is_err());
    let mut unreachable = poll.clone();
    unreachable.number_of_first_retries = 0;
    assert!(unreachable.validate().is_err());
    let mut backwards = poll.clone();
    backwards.interval_for_second_set_of_retries = 10;
    backwards.number_of_second_retries = 1;
    assert!(backwards.validate().is_err());
    let request = Request::poll_schedule("RSS-MDM", &poll).unwrap();
    assert!(request.validate_poll().is_ok());
    assert!(request.validate_provider("RSS-MDM").is_ok());
    assert!(request.validate_provider("OTHER").is_err());
    let Request::Sequence { mut operations } = request else {
        panic!()
    };
    operations.pop();
    assert!(Request::Sequence { operations }.validate_poll().is_err());
}
