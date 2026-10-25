use rss_mdm_recovery_credentials::{Binding, Coordinates, KeyRing, Recipient, Subject};
use uuid::Uuid;
use zeroize::Zeroizing;

fn ring(active: &str, old: bool) -> KeyRing {
    let mut keys = vec![("next".into(), Zeroizing::new(vec![29; 32]))];
    if old {
        keys.push(("first".into(), Zeroizing::new(vec![17; 32])))
    }
    KeyRing::new(active.into(), keys).unwrap()
}
fn coordinate() -> Coordinates {
    Coordinates {
        tenant: Uuid::new_v4(),
        material: Uuid::new_v4(),
        binding: Binding {
            device: "device-one".into(),
            registration: Uuid::new_v4(),
            generation: 1,
            subject: Subject::RecoveryLock,
        },
        version: 1,
    }
}
#[test]
fn stored_material_survives_restart_and_rotation_but_not_coordinate_substitution() {
    let c = coordinate();
    let plaintext = b"test-recovery-password";
    let original = ring("first", true).seal(&c, plaintext).unwrap();
    let rotated = ring("next", true);
    assert_eq!(
        rotated.open("first", &c, &original).unwrap().expose(),
        plaintext
    );
    let replacement = rotated
        .seal(&c, rotated.open("first", &c, &original).unwrap().expose())
        .unwrap();
    assert_eq!(
        ring("next", false)
            .open("next", &c, &replacement)
            .unwrap()
            .expose(),
        plaintext
    );
    assert!(ring("next", false).open("first", &c, &original).is_err());
    let mut mutations = Vec::new();
    let mut v = c.clone();
    v.tenant = Uuid::new_v4();
    mutations.push(v);
    let mut v = c.clone();
    v.material = Uuid::new_v4();
    mutations.push(v);
    let mut v = c.clone();
    v.binding.device = "other".into();
    mutations.push(v);
    let mut v = c.clone();
    v.binding.registration = Uuid::new_v4();
    mutations.push(v);
    let mut v = c.clone();
    v.binding.generation += 1;
    mutations.push(v);
    let mut v = c.clone();
    v.version += 1;
    mutations.push(v);
    let mut v = c.clone();
    v.binding.subject = Subject::Filevault {
        custody: Uuid::new_v4(),
        epoch: 1,
    };
    mutations.push(v);
    for modified in mutations {
        assert!(rotated.open("first", &modified, &original).is_err());
    }
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(rotated.open("first", &c, &tampered).is_err());
    assert!(!original.windows(plaintext.len()).any(|w| w == plaintext));
}
#[test]
fn bad_configuration_cannot_replace_a_missing_key() {
    assert!(
        KeyRing::new(
            "absent".into(),
            vec![("present".into(), Zeroizing::new(vec![1; 32]))]
        )
        .is_err()
    );
    assert!(
        KeyRing::new(
            "first".into(),
            vec![("first".into(), Zeroizing::new(vec![1; 31]))]
        )
        .is_err()
    );
    assert!(
        KeyRing::new(
            "first".into(),
            vec![
                ("first".into(), Zeroizing::new(vec![1; 32])),
                ("alias".into(), Zeroizing::new(vec![1; 32]))
            ]
        )
        .is_err()
    );
}
#[test]
fn cms_uses_exact_recipient_and_rejects_plaintext_or_other_key() {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        cms::{CMSOptions, CmsContentInfo},
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        stack::Stack,
        symm::Cipher,
        x509::{X509, X509NameBuilder},
    };
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "recovery-test").unwrap();
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
    let certificate = certificate.build();
    let recipient = Recipient::from_pem(
        &certificate.to_pem().unwrap(),
        &key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    let mut recipients = Stack::new().unwrap();
    recipients.push(certificate).unwrap();
    let cms = CmsContentInfo::encrypt(
        &recipients,
        b"ABCD-EFGH-IJKL-MNOP-QRST-UVWX",
        Cipher::aes_256_cbc(),
        CMSOptions::BINARY,
    )
    .unwrap()
    .to_der()
    .unwrap();
    assert_eq!(
        recipient.decrypt(recipient.id(), &cms).unwrap().as_slice(),
        b"ABCD-EFGH-IJKL-MNOP-QRST-UVWX"
    );
    assert!(recipient.decrypt("different-recipient", &cms).is_err());
    assert!(recipient.decrypt(recipient.id(), b"plaintext").is_err());
}
