use super::*;
#[test]
fn identity_keys_are_unique_and_nested_input_is_bounded() {
    let duplicate = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>UDID</key><string>a</string><key>UDID</key><string>b</string></dict></plist>";
    assert!(decode(duplicate).is_err());
    let deep = format!(
        "<plist>{}x{}</plist>",
        "<array>".repeat(128),
        "</array>".repeat(128)
    );
    assert!(decode(deep.as_bytes()).is_err());
}
#[test]
fn acknowledgement_requires_correlation_and_user_messages_do_not_become_devices() {
    let message =
        |xml: &str| format!("<plist version=\"1.0\"><dict>{xml}</dict></plist>").into_bytes();
    assert!(
        management(
            &decode(&message(
                "<key>UDID</key><string>d</string><key>Status</key><string>Acknowledged</string>"
            ))
            .unwrap()
        )
        .is_err()
    );
    let user = decode(&message("<key>UDID</key><string>d</string><key>UserID</key><string>user</string><key>Status</key><string>Idle</string>")).unwrap();
    assert!(
        management(&user).is_err(),
        "non-GUID user cannot become device"
    );
    let valid = dictionary([
        ("UDID", "d".into()),
        ("UserID", "a0000000-0000-4000-8000-000000000001".into()),
        ("Status", "Idle".into()),
    ]);
    assert!(management(&valid).unwrap().user.is_some());
    assert!(device(&valid).is_err());
}

#[test]
fn native_plist_dates_remain_dates_instead_of_becoming_strings() {
    let xml = b"<plist version=\"1.0\"><dict><key>Timestamp</key><date>2026-10-01T00:00:00Z</date><key>Certificate</key><data>AQID</data></dict></plist>";
    let values = decode(xml).unwrap();
    assert!(matches!(values.get("Timestamp"), Some(Value::Date(_))));
    assert_eq!(
        values.get("Certificate").and_then(Value::as_data),
        Some([1, 2, 3].as_slice())
    );
}

#[test]
fn user_authentication_and_bootstrap_never_accept_account_authority() {
    let user = Uuid::new_v4();
    let mut request = dictionary([
        ("MessageType", "UserAuthenticate".into()),
        ("UDID", "device".into()),
        ("UserID", user.to_string().into()),
    ]);
    assert!(matches!(checkin(&request),Ok(CheckIn::UserAuthenticate{user:id,..}) if id==user));
    request.insert("DigestResponse".into(), "directory-password".into());
    assert!(matches!(checkin(&request), Err(Error::Unsupported)));
    let mut request = dictionary([("MessageType", "SetBootstrapToken".into())]);
    assert!(matches!(
        checkin(&request),
        Ok(CheckIn::SetBootstrapToken { token: None })
    ));
    request.insert("BootstrapToken".into(), Value::Data(vec![]));
    assert!(matches!(
        checkin(&request),
        Ok(CheckIn::SetBootstrapToken { token: Some([]) })
    ));
    request.insert("UserID".into(), user.to_string().into());
    assert!(matches!(checkin(&request), Err(Error::Unsupported)));
}
