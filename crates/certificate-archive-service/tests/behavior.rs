use crate::*;
use crate::{generation, materials, protection};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;
const TENANT: &str = "11111111-1111-4111-8111-111111111111";
fn input(profile: Profile) -> Generate {
    Generate {
        entry_id: uuid::Uuid::new_v4(),
        expected_revision: 0,
        metadata: Metadata {
            name: "Test certificate".into(),
            category: "custom".into(),
            labels: vec![],
            usages: vec![],
            owner: "test".into(),
            notes: "".into(),
        },
        profile,
        algorithm: Algorithm::P256,
        common_name: "test.example".into(),
        organization: "Test".into(),
        sans: vec![],
        days: 0,
        issuer: None,
        scep_url: None,
    }
}
#[test]
fn encrypted_key_survives_restart_rewrap_and_rejects_wrong_coordinates() {
    let key = protection::random::<32>().unwrap();
    let salt = protection::random::<16>().unwrap();
    let password = protection::derive("first secret password", &salt).unwrap();
    let wrapped = protection::wrap(TENANT, 1, password.as_ref(), &key).unwrap();
    drop(password);
    let password = protection::derive("first secret password", &salt).unwrap();
    let opened = protection::unwrap(TENANT, 1, password.as_ref(), &wrapped).unwrap();
    assert_eq!(opened.as_ref().as_ref(), key);
    let bad = protection::derive("incorrect password text", &salt).unwrap();
    assert!(matches!(
        protection::unwrap(TENANT, 1, bad.as_ref(), &wrapped),
        Err(Error::Password)
    ));
    assert!(protection::unwrap(TENANT, 2, password.as_ref(), &wrapped).is_err());
    assert!(
        protection::unwrap(
            "22222222-2222-4222-8222-222222222222",
            1,
            password.as_ref(),
            &wrapped
        )
        .is_err()
    );
    let id = uuid::Uuid::new_v4();
    let protect = protection::protector(&key).unwrap();
    let material = protect
        .seal_bytes(
            b"historic private material",
            &protection::material_aad(TENANT, id, 1).unwrap(),
        )
        .unwrap();
    let new_salt = protection::random::<16>().unwrap();
    let new = protection::derive("second secret password", &new_salt).unwrap();
    let rewrapped = protection::wrap(TENANT, 2, new.as_ref(), opened.as_ref().as_ref()).unwrap();
    let restored = protection::unwrap(TENANT, 2, new.as_ref(), &rewrapped).unwrap();
    assert_eq!(
        protection::protector(restored.as_ref().as_ref())
            .unwrap()
            .open_bytes(&material, &protection::material_aad(TENANT, id, 1).unwrap())
            .unwrap()
            .expose(),
        b"historic private material"
    );
    assert!(
        protect
            .open_bytes(&material, &protection::material_aad(TENANT, id, 2).unwrap())
            .is_err()
    );
    let mut corrupt = material;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        protect
            .open_bytes(&corrupt, &protection::material_aad(TENANT, id, 1).unwrap())
            .is_err()
    );
}
#[test]
fn generated_ca_and_https_have_real_signatures_san_and_matching_keys() {
    let now = 1_790_000_000;
    let (ca, ca_facts) = generation::generate(&input(Profile::Ca), None, now).unwrap();
    assert!(ca_facts.iter().any(|f| f.contains_private_key));
    let mut request = input(Profile::Https);
    request.sans = vec!["test.example".into(), "127.0.0.1".into()];
    request.days = 30;
    request.issuer = Some(VersionRef {
        entry_id: uuid::Uuid::new_v4(),
        version: 1,
    });
    let (bundle, facts) = generation::generate(&request, Some(&ca), now).unwrap();
    let find = |b: &model::Bundle, name: &str| {
        openssl::x509::X509::from_pem(
            &STANDARD
                .decode(
                    b.files
                        .iter()
                        .find(|f| f.name == name)
                        .unwrap()
                        .data
                        .as_bytes(),
                )
                .unwrap(),
        )
        .unwrap()
    };
    let issuer = find(&ca, "certificate.pem");
    let leaf = find(&bundle, "certificate.pem");
    assert!(leaf.verify(&issuer.public_key().unwrap()).unwrap());
    assert_eq!(
        facts
            .iter()
            .flat_map(|f| &f.certificates)
            .find(|c| c.subject.contains("test.example") && c.not_after == now + 30 * 86400)
            .unwrap()
            .sans,
        request.sans
    );
    request.days = 36500;
    assert!(matches!(
        generation::generate(&request, Some(&ca), now),
        Err(Error::Malformed)
    ));
}
#[test]
fn pkcs12_password_key_binding_and_opaque_archive_are_explicit() {
    let (bundle, _) = generation::generate(&input(Profile::Ca), None, 1_790_000_000).unwrap();
    let key_file = bundle
        .files
        .iter()
        .find(|f| f.name.ends_with(".pk8"))
        .unwrap();
    let key = openssl::pkey::PKey::private_key_from_pkcs8(
        &STANDARD.decode(key_file.data.as_bytes()).unwrap(),
    )
    .unwrap();
    let cert = openssl::x509::X509::from_pem(
        &STANDARD
            .decode(
                bundle
                    .files
                    .iter()
                    .find(|f| f.name == "certificate.pem")
                    .unwrap()
                    .data
                    .as_bytes(),
            )
            .unwrap(),
    )
    .unwrap();
    let mut builder = openssl::pkcs12::Pkcs12::builder();
    builder.pkey(&key).cert(&cert).name("test");
    let pfx = builder.build2("input password").unwrap().to_der().unwrap();
    let mut file = ImportFile {
        name: "test.p12".into(),
        format: Format::Pkcs12,
        data: Zeroizing::new(STANDARD.encode(pfx)),
        password: Some(Zeroizing::new("input password".into())),
    };
    let (saved, facts) = materials::parse(&[file]).unwrap();
    assert!(facts[0].contains_private_key);
    assert!(saved.files.iter().any(|f| f.name.ends_with("key.pk8")));
    file = ImportFile {
        name: "test.p12".into(),
        format: Format::Pkcs12,
        data: Zeroizing::new(
            saved
                .files
                .iter()
                .find(|f| f.name == "test.p12")
                .unwrap()
                .data
                .to_string(),
        ),
        password: Some(Zeroizing::new("wrong".into())),
    };
    assert!(matches!(materials::parse(&[file]), Err(Error::Material)));
    let opaque = ImportFile {
        name: "external.bin".into(),
        format: Format::Opaque,
        data: Zeroizing::new(STANDARD.encode(b"external material")),
        password: None,
    };
    let (_, facts) = materials::parse(&[opaque]).unwrap();
    assert!(facts[0].certificates.is_empty());
    let malformed = ImportFile {
        name: "bad.pem".into(),
        format: Format::Certificate,
        data: Zeroizing::new(STANDARD.encode(b"external material")),
        password: None,
    };
    assert!(matches!(
        materials::parse(&[malformed]),
        Err(Error::Material)
    ));
}
#[test]
fn request_binding_rejects_another_generated_identity() {
    let (_, request) = generation::generate(&input(Profile::Csr), None, 1_790_000_000).unwrap();
    let (_, certs) = generation::generate(&input(Profile::Ca), None, 1_790_000_000).unwrap();
    assert!(matches!(
        materials::check_request(&request, &certs),
        Err(Error::KeyMismatch)
    ));
    let mut apns = input(Profile::ApnsCsr);
    assert!(matches!(
        generation::generate(&apns, None, 1_790_000_000),
        Err(Error::Malformed)
    ));
    apns.algorithm = Algorithm::Rsa2048;
    assert!(
        generation::generate(&apns, None, 1_790_000_000)
            .unwrap()
            .1
            .iter()
            .all(|f| f.certificates.is_empty())
    );
}
