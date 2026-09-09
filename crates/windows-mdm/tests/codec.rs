use rss_mdm_windows_mdm::{CodecLimits, syncml};

#[test]
fn historical_initialization_is_only_untrusted_protocol_data() {
    let message = syncml::decode(
        include_bytes!("fixtures/initialization.xml"),
        &CodecLimits::default(),
    )
    .unwrap();
    assert_eq!(message.header.source, "test-device");
    assert_eq!(message.commands.len(), 2);
    assert!(message.final_message);
}

#[test]
fn duplicate_header_is_rejected() {
    let xml = include_str!("fixtures/results.xml")
        .replace("<MsgID>2</MsgID>", "<MsgID>2</MsgID><MsgID>3</MsgID>");
    assert!(syncml::decode(xml.as_bytes(), &CodecLimits::default()).is_err());
}

#[test]
fn dtd_is_rejected_before_entity_resolution() {
    let xml = b"<!DOCTYPE SyncML [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><SyncML>&e;</SyncML>";
    assert!(syncml::decode(xml, &CodecLimits::default()).is_err());
}

#[test]
fn empty_results_data_is_a_present_empty_value() {
    let xml = include_str!("fixtures/results.xml").replace("<Data>TEST-DEVICE</Data>", "<Data/>");
    assert!(syncml::decode(xml.as_bytes(), &CodecLimits::default()).is_ok());
}
#[test]
fn malformed_xml_declaration_is_rejected() {
    let base = include_str!("fixtures/initialization.xml");
    for declaration in [
        "<?xml version=\"1.0\" encoding=\"utf-8\" encoding=\"utf-8\"?>",
        "<?xml version=\"1.0\" standalone=\"invalid\"?>",
        "<?xml version=\"1.0\" unknown=\"x\"?>",
    ] {
        let xml = base.replacen("<?xml version=\"1.0\" encoding=\"utf-8\"?>", declaration, 1);
        assert!(
            syncml::decode(xml.as_bytes(), &CodecLimits::default()).is_err(),
            "{declaration}"
        );
    }
}

#[test]
fn syncml_budgets_apply_to_decode_encode_and_model_construction() {
    let xml = include_bytes!("fixtures/results.xml");
    let l = CodecLimits::default();
    let m = syncml::decode(xml, &l).unwrap();
    let encoded = syncml::encode(&m, &l).unwrap();
    for (ok, bad) in [
        (
            CodecLimits {
                syncml_bytes: xml.len(),
                ..l.clone()
            },
            CodecLimits {
                syncml_bytes: xml.len() - 1,
                ..l.clone()
            },
        ),
        (
            CodecLimits {
                commands: 2,
                ..l.clone()
            },
            CodecLimits {
                commands: 1,
                ..l.clone()
            },
        ),
        (
            CodecLimits {
                items: 5,
                ..l.clone()
            },
            CodecLimits {
                items: 4,
                ..l.clone()
            },
        ),
    ] {
        assert!(syncml::decode(xml, &ok).is_ok());
        assert!(syncml::decode(xml, &bad).is_err());
    }
    assert!(
        syncml::encode(
            &m,
            &CodecLimits {
                syncml_bytes: encoded.len(),
                ..l.clone()
            }
        )
        .is_ok()
    );
    assert!(
        syncml::encode(
            &m,
            &CodecLimits {
                syncml_bytes: encoded.len() - 1,
                ..l.clone()
            }
        )
        .is_err()
    );
    for no in [
        CodecLimits {
            commands: 1,
            ..l.clone()
        },
        CodecLimits {
            items: 4,
            ..l.clone()
        },
    ] {
        assert!(syncml::encode(&m, &no).is_err());
    }
    let mut value = m.clone();
    let syncml::Command::Results(r) = &mut value.commands[1] else {
        panic!()
    };
    r.items[0].data.as_mut().unwrap().0 = "x".repeat(l.field_bytes);
    assert!(syncml::encode(&value, &l).is_ok());
    let syncml::Command::Results(r) = &mut value.commands[1] else {
        panic!()
    };
    r.items[0].data.as_mut().unwrap().0.push('x');
    assert!(syncml::encode(&value, &l).is_err());
}
#[test]
fn namespaces_prefixes_bom_and_entities_preserve_semantics() {
    let l = CodecLimits::default();
    let xml = include_str!("fixtures/initialization.xml");
    let original = syncml::decode(xml.as_bytes(), &l).unwrap();
    let bom = format!("\u{feff}{xml}");
    assert_eq!(syncml::decode(bom.as_bytes(), &l).unwrap(), original);
    let entity = xml.replace("<Data>Example</Data>", "<Data>&#69;xample</Data>");
    assert_eq!(syncml::decode(entity.as_bytes(), &l).unwrap(), original);
    let wrong = xml.replace("SYNCML:SYNCML1.2", "urn:wrong");
    assert!(syncml::decode(wrong.as_bytes(), &l).is_err());
    let prefix = xml
        .replace("<SyncML xmlns=", "<s:SyncML xmlns:s=")
        .replace("</SyncML>", "</s:SyncML>");
    assert!(syncml::decode(prefix.as_bytes(), &l).is_err()); // children lost their namespace
}
#[test]
fn initialization_cannot_become_a_general_replace_command() {
    let xml = include_str!("fixtures/initialization.xml");
    let l = CodecLimits::default();
    for bad in [
        xml.replace("1201", "1226"),
        xml.replace("./DevInfo/Man", "./DevInfo/DevId"),
        xml.replace("./DevInfo/Man", "./Vendor/MSFT/Policy"),
        xml.replace("<CmdID>3</CmdID>", "<CmdID>2</CmdID>"),
        xml.replace("<Final/>", ""),
        xml.replace("<CmdID>2</CmdID>", "<CmdID>4294967296</CmdID>"),
    ] {
        assert!(syncml::decode(bad.as_bytes(), &l).is_err());
    }
}
#[test]
fn binary_input_and_malformed_trailing_content_are_rejected() {
    let l = CodecLimits::default();
    assert!(syncml::decode(&[0xff, 0xfe, 0, 0], &l).is_err());
    let xml = include_str!("fixtures/results.xml");
    for bad in [
        format!("{xml}<extra/>"),
        xml.replace("</SyncML>", ""),
        xml.replace("<Final/>", "<Final/><Final/>"),
        xml.replace("<Results>", "<Results><Unknown/>"),
        xml.replace("<CmdID>2</CmdID>", "<CmdID>0</CmdID>"),
    ] {
        assert!(syncml::decode(bad.as_bytes(), &l).is_err());
    }
}
#[test]
fn invalid_xml_names_and_cdata_outside_document_are_rejected() {
    let l = CodecLimits::default();
    let xml = include_str!("fixtures/initialization.xml");
    let content = xml.split_once("?>").unwrap().1;
    let numeric = content
        .replace("<SyncML xmlns=", "<1:SyncML xmlns:1=")
        .replace("</SyncML>", "</1:SyncML>")
        .replace("<SyncHdr>", "<SyncHdr xmlns=\"SYNCML:SYNCML1.2\">")
        .replace("<SyncBody>", "<SyncBody xmlns=\"SYNCML:SYNCML1.2\">");
    for bad in [
        numeric,
        format!("<![CDATA[ ]]>{content}"),
        format!("&#32;{content}"),
    ] {
        assert!(syncml::decode(bad.as_bytes(), &l).is_err());
    }
}

mod common;

#[test]
fn independent_syncml_wire_goldens() {
    let l = CodecLimits::default();
    for xml in [
        include_bytes!("fixtures/initialization.xml").as_slice(),
        include_bytes!("fixtures/results.xml").as_slice(),
        include_bytes!("fixtures/get.xml").as_slice(),
    ] {
        let model = syncml::decode(xml, &l).unwrap();
        assert_eq!(
            common::canonical(&syncml::encode(&model, &l).unwrap()),
            common::canonical(xml)
        );
    }
}
#[test]
fn identifier_and_uri_budgets_are_symmetric() {
    let defaults = CodecLimits::default();
    let mut model = syncml::decode(include_bytes!("fixtures/results.xml"), &defaults).unwrap();
    let syncml::Command::Results(r) = &mut model.commands[1] else {
        panic!()
    };
    r.id = 12345678;
    let xml = syncml::encode(&model, &defaults).unwrap();
    assert!(
        syncml::decode(
            &xml,
            &CodecLimits {
                identifier_bytes: 8,
                ..defaults.clone()
            }
        )
        .is_ok()
    );
    assert!(
        syncml::encode(
            &model,
            &CodecLimits {
                identifier_bytes: 8,
                ..defaults.clone()
            }
        )
        .is_ok()
    );
    assert!(
        syncml::decode(
            &xml,
            &CodecLimits {
                identifier_bytes: 7,
                ..defaults.clone()
            }
        )
        .is_err()
    );
    assert!(
        syncml::encode(
            &model,
            &CodecLimits {
                identifier_bytes: 7,
                ..defaults.clone()
            }
        )
        .is_err()
    );
    model.header.source = format!("urn:{}", "x".repeat(252));
    let xml = syncml::encode(&model, &defaults).unwrap();
    for encode in [true, false] {
        let yes = CodecLimits {
            uri_bytes: 256,
            ..defaults.clone()
        };
        let no = CodecLimits {
            uri_bytes: 255,
            ..defaults.clone()
        };
        if encode {
            assert!(syncml::encode(&model, &yes).is_ok());
            assert!(syncml::encode(&model, &no).is_err());
        } else {
            assert!(syncml::decode(&xml, &yes).is_ok());
            assert!(syncml::decode(&xml, &no).is_err());
        }
    }
}
#[test]
fn alternate_and_escaped_namespace_names_are_equivalent() {
    let l = CodecLimits::default();
    let xml = include_str!("fixtures/initialization.xml");
    let original = syncml::decode(xml.as_bytes(), &l).unwrap();
    let mut prefixed = xml.replace("xmlns=", "xmlns:管理=");
    for name in [
        "SyncML",
        "SyncHdr",
        "SyncBody",
        "VerDTD",
        "VerProto",
        "SessionID",
        "MsgID",
        "Target",
        "Source",
        "LocURI",
        "Alert",
        "CmdID",
        "Data",
        "Replace",
        "Item",
        "Final",
    ] {
        prefixed = prefixed
            .replace(&format!("<{name}"), &format!("<管理:{name}"))
            .replace(&format!("</{name}>"), &format!("</管理:{name}>"));
    }
    assert_eq!(syncml::decode(prefixed.as_bytes(), &l).unwrap(), original);
    assert_eq!(
        syncml::decode(
            xml.replace("SYNCML:SYNCML1.2", "SYNCML:SYNCML1.&#50;")
                .as_bytes(),
            &l
        )
        .unwrap(),
        original
    );
}
#[test]
fn status_detail_wire_order_and_empty_body() {
    let l = CodecLimits::default();
    let xml = include_bytes!("fixtures/status-details.xml");
    let m = syncml::decode(xml, &l).unwrap();
    let syncml::Command::Status(s) = &m.commands[1] else {
        panic!()
    };
    assert_eq!(s.code, 404);
    assert_eq!(s.items.len(), 1);
    assert_eq!(s.target_refs, vec!["./DevDetail/SwV"]);
    assert_eq!(
        common::canonical(&syncml::encode(&m, &l).unwrap()),
        common::canonical(xml)
    );
    let mut empty = m.clone();
    empty.commands.clear();
    assert!(syncml::encode(&empty, &l).is_err());
    let xml = std::str::from_utf8(xml).unwrap();
    let before = xml.split("<SyncBody>").next().unwrap();
    let empty = format!("{before}<SyncBody><Final/></SyncBody></SyncML>");
    assert!(syncml::decode(empty.as_bytes(), &l).is_err());
}
