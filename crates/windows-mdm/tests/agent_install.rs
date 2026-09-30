use rss_mdm_windows_mdm::{CodecLimits, agent_install::Installer, syncml::*};
#[test]
fn installer_round_trip_is_fixed_and_correlated() {
    let installer = Installer::new(
        "11111111-1111-4111-8111-111111111111",
        "1.2.3",
        "https://mdm.example.test/agent/package",
        [7; 32],
        "22222222-2222-4222-8222-222222222222",
    )
    .unwrap();
    // Microsoft CSP's Add and Exec both target DownloadInstall; the job uses XML metadata.
    for command in [installer.prepare(10), installer.install(11)] {
        let Command::AgentInstall { command, .. } = command else {
            panic!("closed Agent command");
        };
        assert_eq!(
            command.target().unwrap(),
            "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7B11111111-1111-4111-8111-111111111111%7D/DownloadInstall"
        );
    }
    let message = Message {
        header: Header {
            session_id: 1,
            message_id: 1,
            target: "device".into(),
            source: "server".into(),
            credential: None,
            meta: None,
        },
        commands: vec![installer.prepare(10), installer.install(11)],
        final_message: true,
    };
    let (bytes, _) = encode_request(&message, &CodecLimits::default()).unwrap();
    assert_eq!(decode(&bytes, &CodecLimits::default()).unwrap(), message);
    let xml = String::from_utf8(bytes).unwrap();
    assert!(xml.contains("<Add>") && xml.contains("<Exec>"));
    assert!(xml.contains(">xml</Format>") && xml.contains(">text/plain</Type>"));
    assert!(xml.contains(
        "/quiet /norestart RSS_INSTALLATION_OPERATION=22222222-2222-4222-8222-222222222222"
    ));
}
#[test]
fn installer_rejects_unbounded_or_injected_inputs() {
    let product = "11111111-1111-4111-8111-111111111111";
    for (version, url, operation) in [
        ("1.0 /evil", "https://mdm.example.test/agent", product),
        ("1.0", "http://mdm.example.test/agent", product),
        ("1.0", "https://user:secret@mdm.example.test/agent", product),
        ("1.0", "https://mdm.example.test/agent", "x & evil"),
    ] {
        assert!(Installer::new(product, version, url, [7; 32], operation).is_err());
    }
}

#[test]
fn csp_status_distinguishes_progress_failure_and_user_session() {
    use rss_mdm_windows_mdm::agent_install::{Progress::*, progress};
    assert_eq!(progress("20"), Installing);
    assert_eq!(progress("48"), UserRequired);
    assert_eq!(progress("30"), Failed);
    assert_eq!(progress("60"), Failed);
    assert_eq!(progress("70"), Completed);
    for value in ["", "404", "200", "-1"] {
        assert_eq!(progress(value), Unknown);
    }
}
