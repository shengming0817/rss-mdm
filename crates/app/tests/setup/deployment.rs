use super::*;

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
fn replay_and_successor_preserve_host_identity_and_operation() {
    let previous = previous();
    let mut next = binding(&previous);
    let admit = |next: &Binding| {
        admit_successor(&previous, next, &previous.tenant_id, &previous.instance_id)
    };
    assert!(admit(&next).is_ok());
    next.material_digest = "b".repeat(64);
    assert!(admit(&next).is_err());
    next.revision += 1;
    assert!(admit(&next).is_err());
    next.operation_id = uuid::Uuid::new_v4();
    assert!(admit(&next).is_ok());
    next.revision = previous.revision - 1;
    assert!(admit(&next).is_err());
    next = binding(&previous);
    next.host_id = uuid::Uuid::new_v4();
    assert!(admit(&next).is_err());
    assert!(
        admit_successor(
            &previous,
            &binding(&previous),
            "other",
            &previous.instance_id
        )
        .is_err()
    );
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
fn deployment_requires_an_immutable_image() {
    assert!(image(&format!("sha256:{}", "a".repeat(64))).is_ok());
    assert!(image(&format!("registry.example/mdm@sha256:{}", "b".repeat(64))).is_ok());
    for value in [
        "mdm:latest",
        "mdm:v1",
        "sha256:abc",
        "--help",
        "mdm@sha256:",
    ] {
        assert!(image(value).is_err());
    }
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
fn runtime_mounts_are_scoped_to_named_volume_subdirectories() {
    let config = Config {
        server_image: format!("sha256:{}", "a".repeat(64)),
        gateway_image: format!("sha256:{}", "b".repeat(64)),
        certificate_file: "/unused/certificate".into(),
        private_key_file: "/unused/key".into(),
        trust_file: "/unused/ca".into(),
        content_volume: None,
        state_volume: "installation_state".into(),
        network: "installation_default".into(),
        publish_ip: "127.0.0.1".parse().unwrap(),
    };
    let mount = volume_mount(
        &config,
        Path::new("/var/lib/rss-mdm/installation/host/operation/server"),
        "/run/mdm",
        true,
    )
    .unwrap();
    assert_eq!(mount["type"], "volume");
    assert_eq!(
        mount["volume"]["subpath"],
        "installation/host/operation/server"
    );
    assert_eq!(mount["read_only"], true);
    for path in ["/etc", "/var/lib/rss-mdm", "/var/lib/rss-mdm/../secret"] {
        assert!(volume_mount(&config, Path::new(path), "/run/mdm", true).is_err());
    }
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
