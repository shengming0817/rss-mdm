use rss_mdm_windows_mdm::{
    CodecError, CodecLimits, CorrelationError,
    syncml::{self, Command, CommandName, Expected, Reference},
};
const TARGETS: [&str; 5] = [
    "./DevDetail/Ext/Microsoft/DeviceName",
    "./DevDetail/Ext/Microsoft/DNSComputerName",
    "./DevDetail/SwV",
    "./DevDetail/FwV",
    "./DevDetail/Ext/Microsoft/SMBIOSSerialNumber",
];
fn outbound(message_id: u32, command_id: u32) -> syncml::Message {
    let mut m =
        syncml::decode(include_bytes!("fixtures/get.xml"), &CodecLimits::default()).unwrap();
    m.header.message_id = message_id;
    m.commands = vec![Command::Get {
        id: command_id,
        meta: None,
        items: TARGETS
            .iter()
            .map(|uri| syncml::Item {
                source: None,
                target: Some((*uri).into()),
                meta: None,
                data: None,
            })
            .collect(),
    }];
    m
}
fn expected(message_id: u32, command_id: u32) -> Expected {
    let l = CodecLimits::default();
    let (bytes, sent) = syncml::encode_request(&outbound(message_id, command_id), &l).unwrap();
    assert_eq!(
        syncml::decode(&bytes, &l).unwrap(),
        outbound(message_id, command_id)
    );
    Expected::new(sent, 2, &l).unwrap()
}
fn setup() -> (Expected, syncml::Message) {
    (
        expected(1, 4),
        syncml::decode(
            include_bytes!("fixtures/results.xml"),
            &CodecLimits::default(),
        )
        .unwrap(),
    )
}
#[test]
fn exact_references_and_partial_responses_preserve_missing_items() {
    let (e, mut m) = setup();
    let l = CodecLimits::default();
    let out = syncml::correlate(&e, &m, &l).unwrap();
    assert_eq!(out.results.len(), 5);
    assert!(out.missing_results.is_empty());
    let Command::Results(r) = &mut m.commands[1] else {
        panic!()
    };
    let missing = r.items.pop().unwrap().source.unwrap();
    let out = syncml::correlate(&e, &m, &l).unwrap();
    assert_eq!(out.results.len(), 4);
    assert_eq!(
        out.missing_results,
        vec![Reference {
            message_id: 1,
            command_id: 4,
            uri: missing
        }]
    );
    m.commands.truncate(1);
    let out = syncml::correlate(&e, &m, &l).unwrap();
    assert_eq!(out.missing_results.len(), 5);
}
#[test]
fn results_defaults_are_specified_protocol_semantics() {
    let (_, mut m) = setup();
    let e = expected(1, 1);
    let Command::Results(r) = &mut m.commands[1] else {
        panic!()
    };
    r.message_ref = None;
    r.command_ref = None;
    let out = syncml::correlate(&e, &m, &CodecLimits::default()).unwrap();
    assert!(
        out.results
            .iter()
            .all(|i| !i.explicit_message_ref && !i.explicit_command_ref)
    );
    let e = expected(2, 1);
    assert_eq!(
        syncml::correlate(&e, &m, &CodecLimits::default()),
        Err(CorrelationError::Mismatch)
    );
}
#[test]
fn mismatches_duplicates_and_failure_conflicts_never_yield_facts() {
    let (e, m) = setup();
    let l = CodecLimits::default();
    for index in 0..9 {
        let mut bad = m.clone();
        match index {
            0 => bad.header.session_id = 2,
            1 => bad.header.message_id = 1,
            2 => {
                let Command::Results(r) = &mut bad.commands[1] else {
                    panic!()
                };
                r.message_ref = Some(2);
            }
            3 => {
                let Command::Results(r) = &mut bad.commands[1] else {
                    panic!()
                };
                r.command_ref = Some(99);
            }
            4 => {
                let Command::Results(r) = &mut bad.commands[1] else {
                    panic!()
                };
                r.items[0].source = Some("./Other".into());
            }
            5 => {
                let Command::Results(r) = &mut bad.commands[1] else {
                    panic!()
                };
                r.items.push(r.items[0].clone());
            }
            6 => {
                let Command::Results(r) = &mut bad.commands[1] else {
                    panic!()
                };
                r.id = 1;
            }
            7 => {
                let Command::Status(s) = &mut bad.commands[0] else {
                    panic!()
                };
                s.code = 401;
            }
            _ => {
                let mut duplicate = bad.commands[1].clone();
                let Command::Results(r) = &mut duplicate else {
                    panic!()
                };
                r.id = 3;
                bad.commands.push(duplicate);
            }
        }
        assert!(syncml::correlate(&e, &bad, &l).is_err(), "mutation {index}");
    }
}
#[test]
fn requested_command_type_and_expected_set_must_be_unambiguous() {
    let (mut e, m) = setup();
    let l = CodecLimits::default();
    let (_, duplicate) = syncml::encode_request(&outbound(1, 4), &l).unwrap();
    assert_eq!(
        e.record_sent(duplicate, &l),
        Err(CorrelationError::InvalidExpected(CodecError::Duplicate))
    );
    assert!(syncml::correlate(&e, &m, &l).is_ok());
    let mut bad = outbound(2, 4);
    bad.header.session_id = 2;
    let (_, wrong_session) = syncml::encode_request(&bad, &l).unwrap();
    assert_eq!(
        e.record_sent(wrong_session, &l),
        Err(CorrelationError::InvalidExpected(CodecError::InvalidValue))
    );
    bad.header.session_id = 1;
    bad.header.target = "other-device".into();
    let (_, wrong_device) = syncml::encode_request(&bad, &l).unwrap();
    assert!(e.record_sent(wrong_device, &l).is_err());
    assert!(syncml::correlate(&e, &m, &l).is_ok());
    let mut bad = outbound(1, 4);
    let Command::Get { items, .. } = &mut bad.commands[0] else {
        panic!()
    };
    items.push(items[0].clone());
    assert!(matches!(
        syncml::encode_request(&bad, &l),
        Err(CodecError::Duplicate)
    ));
    assert_eq!(
        syncml::correlate(&e, &m, &CodecLimits { items: 4, ..l }),
        Err(CorrelationError::InvalidExpected(CodecError::LimitExceeded))
    );
}
#[test]
fn per_item_statuses_may_share_a_command_but_not_overlap() {
    let (e, mut m) = setup();
    m.commands.truncate(1);
    let status = |id, uri: String| {
        Command::Status(syncml::Status {
            credential: None,
            challenge: None,
            id,
            message_ref: 1,
            command_ref: 4,
            command: CommandName::Get,
            target_refs: vec![uri],
            source_refs: vec![],
            code: 404,
            items: vec![],
        })
    };
    m.commands.push(status(2, TARGETS[0].into()));
    m.commands.push(status(3, TARGETS[1].into()));
    let out = syncml::correlate(&e, &m, &CodecLimits::default()).unwrap();
    assert_eq!(out.statuses.len(), 3);
    assert_eq!(out.missing_results.len(), 5);
    m.commands.push(status(4, TARGETS[0].into()));
    assert!(syncml::correlate(&e, &m, &CodecLimits::default()).is_err());
}

#[test]
fn wire_defaults_keep_presence_through_encoding() {
    let l = CodecLimits::default();
    let xml = include_str!("fixtures/results.xml")
        .replace("<MsgRef>1</MsgRef>", "")
        .replace("<CmdRef>4</CmdRef>", "");
    // Status references remain mandatory; remove only Results refs in the fixture.
    let xml = xml.replacen(
        "<CmdRef>0</CmdRef>",
        "<MsgRef>1</MsgRef><CmdRef>0</CmdRef>",
        1,
    );
    let model = syncml::decode(xml.as_bytes(), &l).unwrap();
    let Command::Results(r) = &model.commands[1] else {
        panic!()
    };
    assert_eq!(r.message_ref, None);
    assert_eq!(r.command_ref, None);
    let expected = expected(1, 1);
    let outcome = syncml::correlate(&expected, &model, &l).unwrap();
    assert!(
        outcome
            .results
            .iter()
            .all(|i| !i.explicit_message_ref && !i.explicit_command_ref)
    );
    let encoded = String::from_utf8(syncml::encode(&model, &l).unwrap()).unwrap();
    let result_body = encoded
        .split("<Results>")
        .nth(1)
        .unwrap()
        .split("</Results>")
        .next()
        .unwrap();
    assert!(!result_body.contains("MsgRef"));
    assert!(!result_body.contains("CmdRef"));
}
#[test]
fn status_order_is_scoped_to_each_original_message() {
    let (mut e, mut m) = setup();
    let (_, second) = syncml::encode_request(&outbound(2, 5), &CodecLimits::default()).unwrap();
    e.record_sent(second, &CodecLimits::default()).unwrap();
    let Command::Status(header) = &mut m.commands[0] else {
        panic!()
    };
    header.message_ref = 2;
    let Command::Results(r) = &m.commands[1] else {
        panic!()
    };
    let targets = r.items.iter().map(|i| i.source.clone().unwrap()).collect();
    m.commands.insert(
        1,
        Command::Status(syncml::Status {
            credential: None,
            challenge: None,
            id: 3,
            message_ref: 1,
            command_ref: 4,
            command: CommandName::Get,
            target_refs: targets,
            source_refs: vec![],
            code: 200,
            items: vec![],
        }),
    );
    assert!(syncml::correlate(&e, &m, &CodecLimits::default()).is_ok());
}

#[test]
fn encoded_snapshot_does_not_follow_later_model_mutation() {
    let l = CodecLimits::default();
    let mut request = outbound(1, 4);
    let (bytes, sent) = syncml::encode_request(&request, &l).unwrap();
    let expected = Expected::new(sent.clone(), 2, &l).unwrap();
    let Command::Get { items, .. } = &mut request.commands[0] else {
        panic!()
    };
    items[0].target = Some("./Other".into());
    let (_, mut response) = setup();
    assert!(syncml::correlate(&expected, &response, &l).is_ok());
    let Command::Results(r) = &mut response.commands[1] else {
        panic!()
    };
    r.items[0].source = Some("./Other".into());
    assert_eq!(
        syncml::correlate(&expected, &response, &l),
        Err(CorrelationError::Mismatch)
    );
    assert_eq!(syncml::decode(&bytes, &l).unwrap(), outbound(1, 4));
    assert!(matches!(
        Expected::new(sent, 0, &l),
        Err(CorrelationError::InvalidExpected(CodecError::InvalidValue))
    ));
    assert!(matches!(
        syncml::encode_request(
            &request,
            &CodecLimits {
                syncml_bytes: bytes.len() - 100,
                ..l
            }
        ),
        Err(CodecError::LimitExceeded)
    ));
}
#[test]
fn accumulating_requests_is_atomic_and_bounded() {
    let l = CodecLimits::default();
    let (mut expected, response) = setup();
    let (_, second) = syncml::encode_request(&outbound(2, 4), &l).unwrap();
    assert_eq!(
        expected.record_sent(
            second.clone(),
            &CodecLimits {
                items: 9,
                ..l.clone()
            }
        ),
        Err(CorrelationError::InvalidExpected(CodecError::LimitExceeded))
    );
    assert!(
        syncml::correlate(&expected, &response, &l)
            .unwrap()
            .missing_results
            .is_empty()
    );
    assert_eq!(
        expected.record_sent(
            second.clone(),
            &CodecLimits {
                commands: 1,
                ..l.clone()
            }
        ),
        Err(CorrelationError::InvalidExpected(CodecError::LimitExceeded))
    );
    expected.record_sent(second, &l).unwrap();
    assert_eq!(
        syncml::correlate(&expected, &response, &l)
            .unwrap()
            .missing_results
            .len(),
        5
    );
    let mut bad = response.clone();
    bad.commands[1] = bad.commands[0].clone();
    assert_eq!(
        syncml::correlate(&expected, &bad, &l),
        Err(CorrelationError::InvalidResponse(CodecError::Duplicate))
    );
    assert!(matches!(
        syncml::encode_request(&response, &l),
        Err(CodecError::Unsupported)
    ));
}
