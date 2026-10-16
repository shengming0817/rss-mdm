use super::*;
#[test]
fn identity_is_canonical_tenant_scoped_and_not_a_csr_claim() {
    let tenant = Uuid::new_v4();
    assert_ne!(
        identity(tenant, "device").unwrap(),
        identity(Uuid::new_v4(), "device").unwrap()
    );
    assert!(
        identity(tenant, "设备:one")
            .unwrap()
            .starts_with(&format!("urn:rss-mdm:agent:v1:{tenant}:"))
    );
    assert!(identity(Uuid::nil(), "device").is_err());
    assert!(identity(tenant, "").is_err());
    assert!(identity(tenant, "device\n").is_err());
}
#[test]
fn malformed_requests_do_not_produce_verified_csr() {
    for bytes in [vec![], vec![0; MAX_CSR + 1], vec![0x30, 0]] {
        assert!(VerifiedAgentCsr::verify(&bytes).is_err());
    }
}

#[test]
fn signed_csr_profile_rejects_substituted_identity_and_usage() {
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            X509NameBuilder, X509Req,
            extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName},
        },
    };
    let strong = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let weak = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
    let ec = PKey::from_ec_key(
        openssl::ec::EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    for (key, digest, subject, extension, valid) in [
        (&strong, MessageDigest::sha256(), "rss-mdm-agent", 0, true),
        (&weak, MessageDigest::sha256(), "rss-mdm-agent", 0, false),
        (&strong, MessageDigest::sha1(), "rss-mdm-agent", 0, false),
        (&ec, MessageDigest::sha256(), "rss-mdm-agent", 0, false),
        (&strong, MessageDigest::sha256(), "claimed-device", 0, false),
        (&strong, MessageDigest::sha256(), "rss-mdm-agent", 1, false),
        (&strong, MessageDigest::sha256(), "rss-mdm-agent", 2, false),
        (&strong, MessageDigest::sha256(), "rss-mdm-agent", 3, false),
    ] {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", subject).unwrap();
        let mut request = X509Req::builder().unwrap();
        request.set_subject_name(&name.build()).unwrap();
        request.set_pubkey(key).unwrap();
        if extension != 0 {
            let value = match extension {
                1 => SubjectAlternativeName::new()
                    .uri("urn:claimed")
                    .build(&request.x509v3_context(None))
                    .unwrap(),
                2 => BasicConstraints::new().critical().ca().build().unwrap(),
                _ => ExtendedKeyUsage::new().server_auth().build().unwrap(),
            };
            let mut extensions = openssl::stack::Stack::new().unwrap();
            extensions.push(value).unwrap();
            request.add_extensions(&extensions).unwrap();
        }
        request.sign(key, digest).unwrap();
        let der = request.build().to_der().unwrap();
        assert_eq!(
            VerifiedAgentCsr::verify(&der).is_ok(),
            valid,
            "profile {subject}/{extension}"
        );
    }
}
