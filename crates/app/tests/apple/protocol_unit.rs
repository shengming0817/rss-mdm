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
    assert!(management(&user).is_err());
}
