use rss_mdm_windows_mdm::{CodecError, CodecLimits, Secret, syncml as s};
fn prefix() -> s::Message {
    s::Message {
        header: s::Header {
            session_id: 1,
            message_id: 2,
            source: "server".into(),
            target: "device".into(),
            credential: None,
            meta: None,
        },
        commands: vec![s::Command::Status(s::Status {
            id: 1,
            message_ref: 2,
            command_ref: 0,
            command: s::CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        })],
        final_message: true,
    }
}
fn replace(data: &str) -> s::Command {
    s::Command::Replace {
        id: 7,
        meta: None,
        items: vec![s::Item {
            more_data: false,
            target: Some("./native/object".into()),
            source: None,
            meta: Some(s::Meta {
                format: Some("chr".into()),
                ..Default::default()
            }),
            data: Some(Secret(data.into())),
        }],
    }
}
#[test]
fn fragments_measure_the_entire_wire_and_preserve_utf8_and_xml_entities() {
    let limits = CodecLimits::default();
    let data = "中文<&>".repeat(400);
    let command = replace(&data);
    let mut offset = 0;
    let mut joined = String::new();
    while offset < data.len() {
        let frame = s::fragment(&prefix(), &command, offset, 1200, &limits).unwrap();
        let bytes = s::encode(&frame.message, &limits).unwrap();
        assert!(bytes.len() <= 1200);
        assert!(frame.end > offset);
        let s::Command::Replace { items, .. } = frame.message.commands.last().unwrap() else {
            panic!()
        };
        assert_eq!(
            items[0].meta.as_ref().unwrap().size,
            (offset == 0).then_some(data.len() as u32)
        );
        assert_eq!(items[0].more_data, frame.end != data.len());
        assert_eq!(frame.message.final_message, frame.end == data.len());
        joined.push_str(&items[0].data.as_ref().unwrap().0);
        offset = frame.end;
    }
    assert_eq!(joined, data);
}
#[test]
fn large_compounds_and_unapproved_exec_are_never_partially_emitted() {
    let limits = CodecLimits::default();
    let c = replace(&"x".repeat(4000));
    for command in [
        s::Command::Atomic {
            id: 8,
            commands: vec![c.clone()],
        },
        s::Command::Sequence {
            id: 8,
            commands: vec![c.clone()],
        },
    ] {
        assert!(s::fragment(&prefix(), &command, 0, 1200, &limits).is_err());
    }
    let s::Command::Replace { id, meta, items } = c else {
        panic!()
    };
    assert_eq!(
        s::fragment(
            &prefix(),
            &s::Command::Exec { id, meta, items },
            0,
            1200,
            &limits
        )
        .err(),
        Some(CodecError::Unsupported)
    );
    assert!(s::fragment(&prefix(), &replace("abc"), 0, 10, &limits).is_err());
    assert!(s::fragment(&prefix(), &replace("中"), 1, 1200, &limits).is_err());
}

#[test]
fn large_native_payload_compiles_before_transport_fragmentation() {
    use rss_mdm_windows_mdm::native::{Context, Request, Scope, Value, Verb};
    let value = format!(
        "<AssessmentsRoot><Assessments><Assessment><TestName>{}</TestName><TestUri>https://example.test</TestUri></Assessment></Assessments></AssessmentsRoot>",
        "chunk-value-".repeat(6000)
    );
    let request = Request::Node {
        node: "./Vendor/MSFT/SecureAssessment/Assessments".into(),
        instance: vec![],
        operation: Verb::Replace,
        value: Some(Value::Text(value)),
    };
    let command = request
        .compile(
            Context {
                enrollment: rss_mdm_windows_mdm::native::Enrollment::Primary,
                build: Some([10, 0, 22621, 521]),
                edition: Some(48),
                scope: Scope::Device,
            },
            7,
        )
        .unwrap()
        .command;
    assert!(
        !s::fragment(&prefix(), &command, 0, 4096, &CodecLimits::default())
            .unwrap()
            .message
            .final_message
    );
}

#[test]
fn peer_object_budget_is_independent_of_fragment_size() {
    let limits = CodecLimits {
        object_bytes: 100,
        ..CodecLimits::default()
    };
    assert_eq!(
        s::fragment(&prefix(), &replace(&"x".repeat(101)), 0, 4096, &limits).err(),
        Some(CodecError::LimitExceeded)
    );
}
