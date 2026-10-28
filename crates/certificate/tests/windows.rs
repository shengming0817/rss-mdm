use super::*;
#[test]
fn signed_csr_requires_strong_rsa_sha256_and_exact_der() {
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509NameBuilder, X509Req},
    };
    for (bits, digest, valid) in [
        (2048, MessageDigest::sha256(), true),
        (1024, MessageDigest::sha256(), false),
        (2048, MessageDigest::sha1(), false),
    ] {
        let key = PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "device").unwrap();
        let mut request = X509Req::builder().unwrap();
        request.set_subject_name(&name.build()).unwrap();
        request.set_pubkey(&key).unwrap();
        request.sign(&key, digest).unwrap();
        let bytes = request.build().to_der().unwrap();
        assert_eq!(Csr::verify(&bytes).is_ok(), valid);
        if valid {
            let mut absent = CertReq::from_der(&bytes).unwrap();
            absent.algorithm.parameters = None;
            assert!(Csr::verify(&absent.to_der().unwrap()).is_ok());
            let mut tail = bytes.clone();
            tail.push(0);
            assert!(matches!(Csr::verify(&tail), Err(Error::CertificateRequest)));
            let mut damaged = bytes;
            *damaged.last_mut().unwrap() ^= 1;
            assert!(matches!(
                Csr::verify(&damaged),
                Err(Error::CertificateRequest)
            ));
        }
    }
}

#[test]
fn renewal_policy_boundaries_preserve_expiration() {
    use crate::windows::RenewalPolicy;
    let now = 1_800_000_000;
    for (remaining, accepted) in [
        (90 * 86400, false),
        (61 * 86400, false),
        (60 * 86400 + 301, false),
        (60 * 86400 + 300, true),
        (60 * 86400 - 300, true),
        (60 * 86400, true),
        (42 * 86400, true),
        (30 * 86400, true),
        (7 * 86400, true),
        (1, true),
        (0, false),
        (-1, false),
    ] {
        assert_eq!(RenewalPolicy::permits(now + remaining, now), accepted);
    }
    assert!(!RenewalPolicy::permits(i64::MAX, -1));
    assert_eq!(RenewalPolicy::RETRY_DAYS, 4);
}
