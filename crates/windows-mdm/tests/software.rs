use rss_mdm_windows_mdm::{
    CodecLimits,
    native::Scope,
    software::{Enforcement, InstallJob, Installer},
    syncml::*,
};
fn job() -> InstallJob {
    InstallJob {
        product: "11111111-1111-4111-8111-111111111111".into(),
        version: "1.2.3".into(),
        content_urls: vec!["https://mdm.example.test/software/package".into()],
        sha256: [7; 32],
        operation: "22222222-2222-4222-8222-222222222222".into(),
        scope: Scope::Device,
        enforcement: Enforcement {
            command_line: "/quiet PROPERTY=value".into(),
            timeout_minutes: 10,
            retry_count: 2,
            retry_interval_minutes: 3,
            download_from_aad: false,
        },
    }
}
#[test]
fn msi_round_trip_uses_native_commands_and_correlation() {
    let installer = Installer::new(job()).unwrap();
    // Microsoft CSP's Add and Exec both target DownloadInstall; the job uses XML metadata.
    for command in [installer.prepare(10), installer.install(11).unwrap()] {
        let (Command::Add { items, .. } | Command::Exec { items, .. }) = command else {
            panic!("native MSI command");
        };
        assert_eq!(
            items[0].target.as_deref().unwrap(),
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
        commands: vec![installer.prepare(10), installer.install(11).unwrap()],
        final_message: true,
    };
    let (bytes, _) = encode_request(&message, &CodecLimits::default()).unwrap();
    assert_eq!(decode(&bytes, &CodecLimits::default()).unwrap(), message);
    let xml = String::from_utf8(bytes).unwrap();
    assert!(xml.contains("<Add>") && xml.contains("<Exec>"));
    assert!(xml.contains(">xml</Format>") && xml.contains(">text/plain</Type>"));
    assert!(xml.contains("/quiet PROPERTY=value"));
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
        let mut input = job();
        input.version = version.into();
        input.content_urls = vec![url.into()];
        input.operation = operation.into();
        assert!(Installer::new(input).is_err());
    }
}

#[test]
fn csp_status_distinguishes_progress_failure_and_user_session() {
    use rss_mdm_windows_mdm::software::{Progress::*, progress};
    assert_eq!(progress("20"), Installing);
    assert_eq!(progress("48"), UserRequired);
    assert_eq!(progress("30"), Failed);
    assert_eq!(progress("60"), Failed);
    assert_eq!(progress("70"), Completed);
    for value in ["", "404", "200", "-1"] {
        assert_eq!(progress(value), Unknown);
    }
}

#[test]
fn msi_enforcement_is_native_input_not_an_agent_brand_rule() {
    let installer = Installer::new(job()).unwrap();
    let Command::Exec { items, .. } = installer.install(1).unwrap() else {
        panic!("native exec")
    };
    let xml = &items[0].data.as_ref().unwrap().0;
    assert!(xml.contains("<CommandLine>/quiet PROPERTY=value</CommandLine>"));
    assert!(xml.contains("<TimeOut>10</TimeOut>"));
    assert!(xml.contains("<RetryCount>2</RetryCount>"));
    assert!(!xml.contains("RSS_INSTALLATION_OPERATION"));
}

#[test]
fn user_installation_scope_and_multiple_locations_are_preserved() {
    let mut input = job();
    input.scope = Scope::User;
    input
        .content_urls
        .push("https://backup.example.test/software.msi".into());
    let installer = Installer::new(input).unwrap();
    let Command::Exec { items, .. } = installer.install(1).unwrap() else {
        panic!("native exec")
    };
    assert!(items[0].target.as_deref().unwrap().starts_with("./User/"));
    assert_eq!(
        items[0]
            .data
            .as_ref()
            .unwrap()
            .0
            .matches("<ContentURL>")
            .count(),
        2
    );
    assert!(
        rss_mdm_windows_mdm::software::property(
            Scope::User,
            "11111111-1111-4111-8111-111111111111",
            "LastError"
        )
        .is_ok()
    );
}
