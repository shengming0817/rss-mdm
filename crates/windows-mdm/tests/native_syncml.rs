use rss_mdm_windows_mdm::{CodecError, CodecLimits, syncml};

fn wire(body: &str) -> String {
    format!(
        "<SyncML xmlns=\"SYNCML:SYNCML1.2\"><SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>1</SessionID><MsgID>1</MsgID><Target><LocURI>device</LocURI></Target><Source><LocURI>server</LocURI></Source></SyncHdr><SyncBody>{body}<Final/></SyncBody></SyncML>"
    )
}

#[test]
fn native_mutations_are_not_limited_to_product_brands() {
    let limits = CodecLimits::default();
    for (verb, data) in [
        ("Add", ""),
        ("Replace", "<Data>value</Data>"),
        ("Delete", ""),
        ("Exec", "<Data>argument</Data>"),
    ] {
        let xml = wire(&format!(
            "<{verb}><CmdID>7</CmdID><Item><Target><LocURI>./Vendor/MSFT/Test/Dynamic</LocURI></Target>{data}</Item></{verb}>"
        ));
        let message = syncml::decode(xml.as_bytes(), &limits).unwrap();
        let (encoded, sent) = syncml::encode_request(&message, &limits).unwrap();
        assert_eq!(syncml::decode(&encoded, &limits).unwrap(), message);
        let expected = syncml::Expected::new(sent, 1, &limits).unwrap();
        let response = wire(&format!(
            "<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef>0</CmdRef><Cmd>SyncHdr</Cmd><Data>200</Data></Status><Status><CmdID>2</CmdID><MsgRef>1</MsgRef><CmdRef>7</CmdRef><Cmd>{verb}</Cmd><TargetRef>./Vendor/MSFT/Test/Dynamic</TargetRef><Data>202</Data></Status>"
        ));
        let response = syncml::decode(response.as_bytes(), &limits).unwrap();
        let receipt = syncml::correlate(&expected, &response, &limits).unwrap();
        assert_eq!(receipt.statuses[1].code, 202);
        let mut wrong = response;
        if let syncml::Command::Status(status) = &mut wrong.commands[1] {
            status.target_refs = vec!["./Vendor/MSFT/Test/Other".into()];
        }
        assert!(syncml::correlate(&expected, &wrong, &limits).is_err());
    }
}

#[test]
fn mutations_reject_missing_duplicate_and_wrong_role_items() {
    for body in [
        "<Delete><CmdID>1</CmdID></Delete>",
        "<Delete><CmdID>1</CmdID><Item><Target><LocURI>./x</LocURI></Target><Data>value</Data></Item></Delete>",
        "<Add><CmdID>1</CmdID><Item><Source><LocURI>./x</LocURI></Source></Item></Add>",
        "<Replace><CmdID>1</CmdID><Item><Target><LocURI>./x</LocURI></Target></Item></Replace>",
    ] {
        assert!(syncml::decode(wire(body).as_bytes(), &CodecLimits::default()).is_err());
    }
    let repeated = "<Item><Target><LocURI>./x</LocURI></Target></Item>";
    assert_eq!(
        syncml::decode(
            wire(&format!(
                "<Delete><CmdID>1</CmdID>{repeated}{repeated}</Delete>"
            ))
            .as_bytes(),
            &CodecLimits::default()
        ),
        Err(CodecError::Duplicate)
    );
}

#[test]
fn grouped_operations_preserve_child_identity_and_windows_atomic_rules() {
    let delete =
        "<Delete><CmdID>3</CmdID><Item><Target><LocURI>./x</LocURI></Target></Item></Delete>";
    let limits = CodecLimits::default();
    for body in [
        format!("<Atomic><CmdID>1</CmdID>{delete}</Atomic>"),
        format!("<Sequence><CmdID>1</CmdID><Atomic><CmdID>2</CmdID>{delete}</Atomic></Sequence>"),
    ] {
        let message = syncml::decode(wire(&body).as_bytes(), &limits).unwrap();
        let (encoded, _) = syncml::encode_request(&message, &limits).unwrap();
        assert_eq!(syncml::decode(&encoded, &limits).unwrap(), message);
        let small = CodecLimits {
            commands: 1,
            ..limits.clone()
        };
        assert_eq!(
            syncml::encode(&message, &small),
            Err(CodecError::LimitExceeded)
        );
    }
    for body in [
        format!("<Atomic><CmdID>1</CmdID><Atomic><CmdID>2</CmdID>{delete}</Atomic></Atomic>"),
        "<Atomic><CmdID>1</CmdID><Get><CmdID>2</CmdID><Item><Target><LocURI>./x</LocURI></Target></Item></Get></Atomic>".into(),
        "<Atomic><CmdID>1</CmdID><Add><CmdID>2</CmdID><Item><Target><LocURI>./x</LocURI></Target></Item></Add><Replace><CmdID>3</CmdID><Item><Target><LocURI>./x</LocURI></Target><Data>x</Data></Item></Replace></Atomic>".into(),
        format!("<Sequence><CmdID>3</CmdID>{delete}</Sequence>"),
    ] {
        assert!(syncml::decode(wire(&body).as_bytes(), &limits).is_err());
    }
}

#[test]
fn asynchronous_alert_retains_native_type_and_rejects_correlator() {
    let body = "<Alert><CmdID>1</CmdID><Data>1226</Data><Correlator>job-7</Correlator><Item><Source><LocURI>./Vendor/MSFT/HealthAttestation/VerifyHealth</LocURI></Source><Meta><Type xmlns=\"syncml:metinf\">com.microsoft.mdm:HealthAttestation.Result</Type><Format xmlns=\"syncml:metinf\">int</Format></Meta><Data>3</Data></Item></Alert>";
    let limits = CodecLimits::default();
    assert_eq!(
        syncml::decode(wire(body).as_bytes(), &limits),
        Err(CodecError::Unsupported)
    );
    let body = body.replace("<Correlator>job-7</Correlator>", "");
    let message = syncml::decode(wire(&body).as_bytes(), &limits).unwrap();
    let encoded = syncml::encode(&message, &limits).unwrap();
    assert_eq!(syncml::decode(&encoded, &limits).unwrap(), message);
    assert!(
        String::from_utf8(encoded)
            .unwrap()
            .contains("com.microsoft.mdm:HealthAttestation.Result")
    );
    let duplicate = body.replace(
        "</Meta>",
        "<Format xmlns=\"syncml:metinf\">chr</Format></Meta>",
    );
    assert_eq!(
        syncml::decode(wire(&duplicate).as_bytes(), &limits),
        Err(CodecError::Duplicate)
    );
}
