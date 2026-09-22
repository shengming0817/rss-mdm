use rss_mdm_windows_mdm::{
    CodecLimits,
    configuration::{Firewall, Platform},
    syncml::{self, Command, Header, Message},
};
#[test]
fn fixed_ddf_and_replace_are_strict_and_roundtrip() {
    let platform = Platform::new("10.0.19045.0", 48).unwrap();
    for enabled in [true, false] {
        let plan = Firewall::compile(enabled, &platform).unwrap();
        let message = Message {
            header: Header {
                session_id: 1,
                message_id: 2,
                source: "server".into(),
                target: "device".into(),
                credential: None,
                meta: None,
            },
            commands: vec![plan.replace(1)],
            final_message: true,
        };
        let (bytes, _) = syncml::encode_request(&message, &CodecLimits::default()).unwrap();
        assert_eq!(
            syncml::decode(&bytes, &CodecLimits::default()).unwrap(),
            message
        );
        assert!(String::from_utf8(bytes).unwrap().contains(if enabled {
            "<Data>true</Data>"
        } else {
            "<Data>false</Data>"
        }));
        assert!(matches!(plan.observe(2), Command::Get { .. }));
        assert!(!plan.supports_cleanup());
    }
    for (version, edition) in [
        ("10.0.15063.0", 48),
        ("10.0.19045.0", 0),
        ("10.0.19045.0", 101),
    ] {
        assert!(Firewall::compile(true, &Platform::new(version, edition).unwrap()).is_err());
    }
    for v in ["", "10", "10.0.x.1", "10.0.19045.0.1"] {
        assert!(Platform::new(v, 48).is_err());
    }
}

#[test]
fn write_wire_and_ack_cannot_escape_the_single_leaf() {
    use rss_mdm_windows_mdm::{
        Secret,
        syncml::{CommandName, Item, Results, Status},
    };
    let config = Firewall::compile(true, &Platform::new("10.0.19045.0", 48).unwrap()).unwrap();
    let sent = Message {
        header: Header {
            session_id: 7,
            message_id: 3,
            target: "device".into(),
            source: "server".into(),
            credential: None,
            meta: None,
        },
        commands: vec![config.replace(42)],
        final_message: true,
    };
    let limits = CodecLimits::default();
    let (wire, token) = syncml::encode_request(&sent, &limits).unwrap();
    let xml = String::from_utf8(wire).unwrap();
    assert!(xml.contains("<Replace><CmdID>42</CmdID><Item><Target><LocURI>./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall</LocURI></Target><Meta><Format xmlns=\"syncml:metinf\">bool</Format></Meta><Data>true</Data></Item></Replace>"));
    for (from, to) in [
        ("DomainProfile", "PublicProfile"),
        ("<Data>true</Data>", "<Data>TRUE</Data>"),
        ("bool</Format>", "int</Format>"),
        ("Replace>", "Delete>"),
    ] {
        assert!(syncml::decode(xml.replace(from, to).as_bytes(), &limits).is_err());
    }
    let expected = syncml::Expected::new(token, 4, &limits).unwrap();
    let mut response = Message {
        header: Header {
            message_id: 4,
            target: "server".into(),
            source: "device".into(),
            ..sent.header.clone()
        },
        commands: vec![Command::Status(Status {
            id: 1,
            message_ref: 3,
            command_ref: 42,
            command: CommandName::Replace,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        })],
        final_message: true,
    };
    response.commands.insert(
        0,
        Command::Status(Status {
            id: 2,
            message_ref: 3,
            command_ref: 0,
            command: CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        }),
    );
    assert!(syncml::correlate(&expected, &response, &limits).is_ok());
    if let Command::Status(s) = &mut response.commands[1] {
        s.command = CommandName::Get;
    }
    assert!(syncml::correlate(&expected, &response, &limits).is_err());
    response.commands = vec![Command::Results(Results {
        id: 1,
        message_ref: Some(3),
        command_ref: Some(42),
        command: Some(CommandName::Get),
        meta: None,
        items: vec![Item {
            source: Some(rss_mdm_windows_mdm::configuration::FIREWALL_URI.into()),
            target: None,
            meta: None,
            data: Some(Secret("true".into())),
        }],
    })];
    assert!(syncml::correlate(&expected, &response, &limits).is_err());
}
