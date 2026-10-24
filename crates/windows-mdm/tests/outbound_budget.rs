use rss_mdm_windows_mdm::{CodecError, CodecLimits, Secret, syncml as s};

fn request(count: u32) -> s::Message {
    let mut message =
        s::decode(include_bytes!("fixtures/get.xml"), &CodecLimits::default()).unwrap();
    let prototype = message.commands.remove(0);
    message.commands = (1..=count)
        .map(|id| {
            let mut command = prototype.clone();
            let s::Command::Get { id: command_id, .. } = &mut command else {
                panic!()
            };
            *command_id = id;
            command
        })
        .collect();
    message
}

#[test]
fn read_batches_reserve_room_for_statuses_and_results() {
    let limits = CodecLimits::default();
    // The real failed exchange fit outbound XML but produced 305 incoming commands.
    let oversized = request(205);
    assert!(s::encode(&oversized, &limits).is_ok());
    assert_eq!(
        s::encode_outbound(&oversized, &limits),
        Err(CodecError::LimitExceeded)
    );

    let request = request(127);
    assert!(s::encode_outbound(&request, &limits).is_ok());
    let (_, sent) = s::encode_request(&request, &limits).unwrap();
    let expected = s::Expected::new(sent, 2, &limits).unwrap();
    let mut response = s::Message {
        header: s::Header {
            session_id: request.header.session_id,
            message_id: 2,
            target: request.header.source.clone(),
            source: request.header.target.clone(),
            credential: None,
            meta: None,
        },
        commands: vec![],
        final_message: true,
    };
    let status = |id, command_ref, command| {
        s::Command::Status(s::Status {
            id,
            message_ref: 1,
            command_ref,
            command,
            code: 200,
            credential: None,
            challenge: None,
            target_refs: vec![],
            source_refs: vec![],
            items: vec![],
        })
    };
    response
        .commands
        .push(status(1, 0, s::CommandName::SyncHdr));
    for command in &request.commands {
        let s::Command::Get { id, items, .. } = command else {
            panic!()
        };
        response
            .commands
            .push(status(id * 2, *id, s::CommandName::Get));
        response.commands.push(s::Command::Results(s::Results {
            id: id * 2 + 1,
            message_ref: Some(1),
            command_ref: Some(*id),
            command: Some(s::CommandName::Get),
            meta: None,
            items: items
                .iter()
                .map(|item| s::Item {
                    source: item.target.clone(),
                    target: None,
                    meta: None,
                    data: Some(Secret("fixture".into())),
                    more_data: false,
                })
                .collect(),
        }));
    }
    let wire = s::encode(&response, &limits).unwrap();
    let parsed = s::decode(&wire, &limits).unwrap();
    let correlated = s::correlate(&expected, &parsed, &limits).unwrap();
    assert_eq!(correlated.results.len(), 127);
    assert!(correlated.missing_results.is_empty());
    assert_eq!(parsed.commands.len(), 255);
}

#[test]
fn multi_item_and_compound_commands_share_the_receipt_budget() {
    let mut message = request(1);
    let s::Command::Get { items, .. } = &mut message.commands[0] else {
        panic!()
    };
    let prototype = items[0].clone();
    *items = (0..4)
        .map(|i| s::Item {
            target: Some(format!("./DevInfo/test{i}")),
            ..prototype.clone()
        })
        .collect();
    let limits = CodecLimits {
        commands: 7,
        ..Default::default()
    };
    assert!(s::encode(&message, &limits).is_ok());
    assert_eq!(
        s::encode_outbound(&message, &limits),
        Err(CodecError::LimitExceeded)
    );
    let limits = CodecLimits {
        commands: 9,
        items: 7,
        ..limits
    };
    assert_eq!(
        s::encode_outbound(&message, &limits),
        Err(CodecError::LimitExceeded)
    );
    assert!(s::encode_outbound(&message, &CodecLimits { items: 8, ..limits }).is_ok());

    let mut message = request(3);
    message.commands = vec![s::Command::Sequence {
        id: 100,
        commands: message.commands,
    }];
    let limits = CodecLimits {
        commands: 7,
        ..Default::default()
    };
    assert!(s::encode(&message, &limits).is_ok());
    assert_eq!(
        s::encode_outbound(&message, &limits),
        Err(CodecError::LimitExceeded)
    );
    assert!(
        s::encode_outbound(
            &message,
            &CodecLimits {
                commands: 8,
                ..limits
            }
        )
        .is_ok()
    );
}
