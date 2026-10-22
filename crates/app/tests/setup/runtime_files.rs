use super::*;

#[test]
fn scep_gateway_publishes_exact_device_paths_with_private_upstream_tls() {
    let mut config: crate::config::Config =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let ca = root.join("ca.pem");
    std::fs::write(&ca, b"public CA certificate").unwrap();
    config.product_origin = "https://mdm.example.test".into();
    config.device_pki = vec![crate::device_pki::Provider {
        purpose: rss_mdm_agent_wire::pki::Purpose::Apple,
        issuer: "a".repeat(64),
        origin: "https://step-ca:9000".into(),
        tls_root_file: ca,
        provisioner: "rss-apple-revocation".into(),
        kid: "apple".into(),
        provisioner_key_file: root.join("not-exported.key"),
        scep_url: Some("https://mdm.example.test/scep/rss".into()),
    }];
    let gateway = Journal::open(&root.join("gateway")).unwrap();
    let rendered = scep_locations(&config, &gateway).unwrap();
    assert!(rendered.contains("location = /scep/rss {"));
    assert!(rendered.contains("location = /scep/rss/pkiclient.exe {"));
    assert!(rendered.contains("proxy_pass https://step-ca:9000/scep/rss;"));
    assert!(rendered.contains("proxy_ssl_verify on;"));
    assert!(rendered.contains("proxy_ssl_name step-ca;"));
    assert!(rendered.contains("proxy_pass_request_headers off;"));
    assert!(!rendered.contains("not-exported.key"));
    assert!(!rendered.contains("location /scep"));
    let duplicate =
        serde_json::from_value(serde_json::to_value(&config.device_pki[0]).unwrap()).unwrap();
    config.device_pki.push(duplicate);
    assert_eq!(scep_locations(&config, &gateway).unwrap(), rendered);
    config.device_pki[1].origin = "https://other-ca:9000".into();
    assert!(scep_locations(&config, &gateway).is_err());
    config.device_pki.pop();
    config.device_pki[0].scep_url = Some("https://mdm.example.test/scep/rss-tenant".into());
    let namespaced = scep_locations(&config, &gateway).unwrap();
    assert!(namespaced.contains("proxy_pass https://step-ca:9000/scep/rss-tenant;"));
    assert!(!namespaced.contains("proxy_pass https://step-ca:9000/scep/rss;"));
    config.device_pki[0].scep_url = Some("https://mdm.example.test/scep/rss%2fadmin".into());
    assert!(scep_locations(&config, &gateway).is_err());
}

#[test]
fn runtime_listeners_cannot_take_the_shared_gateway_port() {
    let mut config: crate::config::Config =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    assert!(validate_listeners(&config).is_ok());
    config.listen.set_port(GATEWAY_PORT);
    assert!(validate_listeners(&config).is_err());
    config.listen.set_port(8081);
    let windows = config.native_protocols.windows.as_mut().unwrap();
    let mut endpoint = serde_json::to_value(&windows.management).unwrap();
    endpoint["listen"] = json!("0.0.0.0:8445");
    windows
        .additional_management
        .push(serde_json::from_value(endpoint).unwrap());
    assert!(validate_listeners(&config).is_err());
}

fn previous() -> Applied {
    Applied {
        host_id: uuid::Uuid::new_v4(),
        operation_id: uuid::Uuid::new_v4(),
        revision: 4,
        material_digest: "a".repeat(64),
        process_generation: uuid::Uuid::new_v4(),
        tenant_id: uuid::Uuid::new_v4().to_string(),
        instance_id: uuid::Uuid::new_v4().to_string(),
    }
}
fn binding(value: &Applied) -> Binding {
    Binding {
        host_id: value.host_id,
        operation_id: value.operation_id,
        revision: value.revision,
        material_digest: value.material_digest.clone(),
    }
}
#[test]
fn health_requires_the_exact_input_and_a_real_process_generation() {
    let mut value = previous();
    let expected = binding(&value);
    assert!(matches(
        &value,
        &expected,
        &value.tenant_id,
        &value.instance_id
    ));
    value.process_generation = uuid::Uuid::nil();
    assert!(!matches(
        &value,
        &expected,
        &value.tenant_id,
        &value.instance_id
    ));
    value.process_generation = uuid::Uuid::new_v4();
    value.revision += 1;
    assert!(!matches(
        &value,
        &expected,
        &value.tenant_id,
        &value.instance_id
    ));
}
#[test]
fn candidate_freezes_material_bytes_before_application_digest() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let original = root.join("external.key");
    std::fs::write(&original, [1u8; 32]).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
    let journal = Journal::open(&root.join("candidate")).unwrap();
    let mut value = json!({"native_protection":{"active_file":original,"historical_files":[],"fingerprint_file":original}});
    freeze(&mut value, &journal).unwrap();
    let digest = super::super::application::fingerprint(&value).unwrap();
    std::fs::write(&original, [2u8; 32]).unwrap();
    let frozen = Path::new(value["native_protection"]["active_file"].as_str().unwrap());
    assert_eq!(std::fs::read(frozen).unwrap(), [1u8; 32]);
    let mut changed = json!({"native_protection":{"active_file":original,"historical_files":[],"fingerprint_file":original}});
    freeze(&mut changed, &journal).unwrap();
    assert_ne!(
        digest,
        super::super::application::fingerprint(&changed).unwrap()
    );
}

#[test]
fn gateway_rotation_freezes_matching_material_and_rejects_a_foreign_key() {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder},
    };
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let foreign = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    certificate.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = root.join("certificate.pem");
    let private = root.join("private.pem");
    let other = root.join("other.pem");
    for (path, bytes) in [
        (&cert, certificate.build().to_pem().unwrap()),
        (&private, key.private_key_to_pem_pkcs8().unwrap()),
        (&other, foreign.private_key_to_pem_pkcs8().unwrap()),
    ] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let rejected = Journal::open(&root.join("rejected")).unwrap();
    assert!(GatewayTls::prepare(&rejected, &cert, &other, &cert).is_err());
    assert!(!rejected.path("gateway.key").unwrap().exists());
    let journal = Journal::open(&root.join("accepted")).unwrap();
    let frozen = GatewayTls::prepare(&journal, &cert, &private, &cert).unwrap();
    assert_eq!(frozen.digest.len(), 64);
    std::fs::write(&private, b"changed external key").unwrap();
    assert_eq!(
        std::fs::read(frozen.private_key_file).unwrap(),
        key.private_key_to_pem_pkcs8().unwrap()
    );
}

#[test]
fn additional_host_content_and_cold_snapshot_follow_its_own_deployment() {
    use super::super::model::Phase;
    use super::super::tenant_hosts::{Slot, additional_runtime};
    use uuid::Uuid;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let primary = Config {
        directory: root.join("primary-runtime"),
        content_volume: Some(root.join("primary-content")),
        probe_address: None,
        certificate_file: root.join("server.crt"),
        private_key_file: root.join("server.key"),
        trust_file: root.join("ca.crt"),
    };
    let mut runtime: Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    runtime["content"] =
        serde_json::json!({"storage":primary.prepare_content_storage().unwrap(),"max_uploads":8});
    std::fs::write(primary.content_directory().join("artifact"), b"primary").unwrap();
    let mut disabled = runtime.clone();
    disabled["content"] = Value::Null;
    assert_eq!(
        primary.content_snapshot(&disabled).unwrap(),
        primary.content_directory()
    );

    let progress = super::super::model::Provisioning {
        operation_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        administrator_id: Some(Uuid::new_v4()),
        host_id: Uuid::new_v4(),
        revision: 1,
        phase: Phase::HostPending,
        blocked: None,
        origin: None,
        application: None,
    };
    for explicit in [true, false] {
        let slot = Slot {
            origin: "https://secondary.example.test".into(),
            listen: "127.0.0.1:8082".parse().unwrap(),
            deployment: Config {
                directory: root.join(if explicit {
                    "explicit-runtime"
                } else {
                    "default-runtime"
                }),
                content_volume: explicit.then(|| root.join("secondary-content")),
                ..primary.clone()
            },
        };
        let mut deferred = runtime.clone();
        deferred["content"] = Value::Null;
        let waiting = additional_runtime(&deferred, &slot, &progress).unwrap();
        let decoded: crate::config::Config = serde_json::from_value(waiting).unwrap();
        assert!(decoded.content.is_none());
        let candidate = additional_runtime(&runtime, &slot, &progress).unwrap();
        let volume = slot.deployment.content_snapshot(&candidate).unwrap();
        assert_ne!(volume, primary.content_directory());
        assert_eq!(candidate["content"]["max_uploads"], 8);
        assert!(matches!(
            slot.deployment.content_snapshot(&runtime),
            Err(Error::Conflict)
        ));
        std::fs::write(volume.join("artifact"), b"secondary").unwrap();
        let journal = Journal::open(&root.join(if explicit {
            "explicit-backup"
        } else {
            "default-backup"
        }))
        .unwrap();
        super::super::snapshot_tree::capture(&journal, "volume", &volume).unwrap();
        std::fs::remove_dir_all(&volume).unwrap();
        super::super::snapshot_tree::restore(&journal, "volume").unwrap();
        assert_eq!(
            std::fs::read(volume.join("artifact")).unwrap(),
            b"secondary"
        );
        assert_eq!(
            std::fs::read(primary.content_directory().join("artifact")).unwrap(),
            b"primary"
        );
        let mut shared = slot;
        shared.deployment.content_volume = primary.content_volume.clone();
        assert_eq!(
            shared.deployment.content_snapshot(&runtime).unwrap(),
            primary.content_snapshot(&runtime).unwrap()
        );
    }
}
