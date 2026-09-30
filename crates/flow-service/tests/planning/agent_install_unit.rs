use super::*;
#[test]
fn package_content_requires_its_own_https_origin() {
    let target = SoftwareTarget::new(Platform::Windows, Architecture::X86_64);
    let mut config = Config {
        content_origin: String::new(),
        packages: BTreeMap::from([(
            target,
            Pin {
                identity: Identity::Windows {
                    product: Uuid::new_v4(),
                    publisher: "RSS".into(),
                },
                package: "RSS.Agent".into(),
                version: "1.2.3".into(),
                sha256: [7; 32],
            },
        )]),
    };
    for origin in [
        "https://mdm.example.test",
        "https://mdm.example.test/",
        "https://[::1]:8443",
    ] {
        config.content_origin = origin.into();
        assert!(config.validate().is_ok(), "{origin}");
    }
    for origin in [
        "",
        "http://mdm.example.test",
        "https://user@mdm.example.test",
        "https://user:secret@mdm.example.test",
        "https://mdm.example.test/path",
        "https://mdm.example.test/?token=secret",
        "https://mdm.example.test/#fragment",
        "https://mdm.example.test/\n",
    ] {
        config.content_origin = origin.into();
        assert!(config.validate().is_err(), "{origin}");
    }
    config.content_origin = format!("https://{}.test", "x".repeat(2048));
    assert!(config.validate().is_err());
    assert!(Config::default().validate().is_ok());
}
