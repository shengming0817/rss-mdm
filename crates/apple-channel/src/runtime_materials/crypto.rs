//! RSA/CSR and certificate checks use OpenSSL; protocol-specific consumers validate again on load.
use super::{Error, Purpose};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{X509, X509NameBuilder, X509ReqBuilder, X509StoreContext, store::X509StoreBuilder},
};
use zeroize::Zeroizing;
pub(super) struct Key {
    pub private: Zeroizing<Vec<u8>>,
    pub csr: String,
    pub public_digest: String,
}
pub(super) fn prepare(tenant: &str, purpose: Purpose, import: Option<&str>) -> Result<Key, Error> {
    let key: PKey<Private> = match import {
        Some(value) if value.len() <= 32768 => {
            PKey::private_key_from_pem(value.as_bytes()).map_err(|_| Error::CertificateRequest)?
        }
        Some(_) => return Err(Error::Malformed),
        None => PKey::from_rsa(Rsa::generate(2048).map_err(|_| Error::CertificateRequest)?)
            .map_err(|_| Error::CertificateRequest)?,
    };
    if key.rsa().is_err() || !(2048..=4096).contains(&key.bits()) {
        return Err(Error::CertificateRequest);
    }
    let mut name = X509NameBuilder::new().map_err(|_| Error::CertificateRequest)?;
    name.append_entry_by_text("CN", &format!("RSS {} {tenant}", purpose.name()))
        .map_err(|_| Error::CertificateRequest)?;
    let mut csr = X509ReqBuilder::new().map_err(|_| Error::CertificateRequest)?;
    csr.set_version(0).map_err(|_| Error::CertificateRequest)?;
    csr.set_subject_name(&name.build())
        .map_err(|_| Error::CertificateRequest)?;
    csr.set_pubkey(&key)
        .map_err(|_| Error::CertificateRequest)?;
    csr.sign(&key, MessageDigest::sha256())
        .map_err(|_| Error::CertificateRequest)?;
    use sha2::{Digest, Sha256};
    Ok(Key {
        private: Zeroizing::new(
            key.private_key_to_pkcs8()
                .map_err(|_| Error::CertificateRequest)?,
        ),
        csr: String::from_utf8(
            csr.build()
                .to_pem()
                .map_err(|_| Error::CertificateRequest)?,
        )
        .map_err(|_| Error::CertificateRequest)?,
        public_digest: format!(
            "{:x}",
            Sha256::digest(
                key.public_key_to_der()
                    .map_err(|_| Error::CertificateRequest)?
            )
        ),
    })
}
pub(super) struct Certificate {
    pub expires: i64,
    pub topic: Option<String>,
    pub digest: String,
}
pub(super) fn certificate(
    purpose: Purpose,
    pem: &str,
    private: &[u8],
    roots: &[Vec<u8>],
    now: i64,
) -> Result<Certificate, Error> {
    if pem.len() > 128 * 1024 || roots.is_empty() || roots.len() > 16 || now <= 0 {
        return Err(Error::CertificateRequest);
    }
    let chain = X509::stack_from_pem(pem.as_bytes()).map_err(|_| Error::CertificateRequest)?;
    if chain.is_empty() || chain.len() > 8 {
        return Err(Error::CertificateRequest);
    }
    let key = PKey::private_key_from_pkcs8(private).map_err(|_| Error::CertificateRequest)?;
    if !chain[0]
        .public_key()
        .map_err(|_| Error::CertificateRequest)?
        .public_eq(&key)
    {
        return Err(Error::CertificateRequest);
    }
    let mut store = X509StoreBuilder::new().map_err(|_| Error::CertificateRequest)?;
    for root in roots {
        store
            .add_cert(X509::from_pem(root).map_err(|_| Error::CertificateRequest)?)
            .map_err(|_| Error::CertificateRequest)?;
    }
    let mut params =
        openssl::x509::verify::X509VerifyParam::new().map_err(|_| Error::CertificateRequest)?;
    params.set_time(now as _);
    store
        .set_param(&params)
        .map_err(|_| Error::CertificateRequest)?;
    let mut intermediates = Stack::new().map_err(|_| Error::CertificateRequest)?;
    for cert in chain.iter().skip(1) {
        intermediates
            .push(cert.clone())
            .map_err(|_| Error::CertificateRequest)?;
    }
    let mut context = X509StoreContext::new().map_err(|_| Error::CertificateRequest)?;
    let (valid, verified_chain) = context
        .init(&store.build(), &chain[0], &intermediates, |c| {
            let valid = c.verify_cert()?;
            let verified = c
                .chain()
                .map(|certs| {
                    certs
                        .iter()
                        .map(|cert| cert.to_der())
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;
            Ok((valid, verified))
        })
        .map_err(|_| Error::CertificateRequest)?;
    if !valid {
        return Err(Error::CertificateRequest);
    }
    use x509_cert::der::Decode;
    let leaf = x509_cert::Certificate::from_der(
        &chain[0].to_der().map_err(|_| Error::CertificateRequest)?,
    )
    .map_err(|_| Error::CertificateRequest)?;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    if leaf
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|_| Error::CertificateRequest)?
        .is_some_and(|(_, bc)| bc.ca)
        || leaf
            .tbs_certificate
            .get::<KeyUsage>()
            .map_err(|_| Error::CertificateRequest)?
            .is_none_or(|(_, usage)| !usage.digital_signature() || usage.key_cert_sign())
    {
        return Err(Error::CertificateRequest);
    }
    if !rss_mdm_certificate::apple::valid(&leaf, now) {
        return Err(Error::CertificateRequest);
    }
    // The selected credential becomes unusable when any certificate in its verified chain
    // expires, including the accepted trust anchor, not just when its leaf expires.
    let expires = verified_chain
        .ok_or(Error::CertificateRequest)?
        .iter()
        .map(|der| {
            let certificate =
                x509_cert::Certificate::from_der(der).map_err(|_| Error::CertificateRequest)?;
            i64::try_from(
                certificate
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs(),
            )
            .map_err(|_| Error::CertificateRequest)
        })
        .collect::<Result<Vec<_>, Error>>()?
        .into_iter()
        .min()
        .ok_or(Error::CertificateRequest)?;
    let topic = if purpose == Purpose::Apns {
        let ids = leaf
            .tbs_certificate
            .subject
            .0
            .iter()
            .flat_map(|r| r.0.iter())
            .filter(|a| a.oid.to_string() == "0.9.2342.19200300.100.1.1")
            .collect::<Vec<_>>();
        if ids.len() != 1 {
            return Err(Error::CertificateRequest);
        }
        let topic = std::str::from_utf8(ids[0].value.value())
            .map_err(|_| Error::CertificateRequest)?
            .to_owned();
        if !topic.starts_with("com.apple.mgmt.") || topic.len() > 255 {
            return Err(Error::CertificateRequest);
        }
        Some(topic)
    } else {
        if purpose == Purpose::Profile {
            rss_mdm_certificate::apple::ProfileSigner::from_bytes(pem.as_bytes(), private, now)?;
        } else {
            rss_mdm_certificate::apple::ManagedAccountTokenSigner::from_bytes(
                pem.as_bytes(),
                private,
                now,
            )?;
        }
        None
    };
    Ok(Certificate {
        expires,
        topic,
        digest: chain_digest(&chain)?,
    })
}

/// Persisted identity binding is checked before time-dependent trust eligibility.
pub(super) fn persisted_digest(pem: &str, private: &[u8]) -> Result<String, Error> {
    let chain = X509::stack_from_pem(pem.as_bytes()).map_err(|_| Error::Conflict)?;
    let leaf = chain.first().ok_or(Error::Conflict)?;
    let key = PKey::private_key_from_pkcs8(private).map_err(|_| Error::Conflict)?;
    if !leaf
        .public_key()
        .map_err(|_| Error::Conflict)?
        .public_eq(&key)
    {
        return Err(Error::Conflict);
    }
    chain_digest(&chain)
}
fn chain_digest(chain: &[X509]) -> Result<String, Error> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    // DER lengths frame the entire supplied chain, so exchanging an intermediate changes
    // the exact candidate identity even when the leaf remains the same.
    for certificate in chain {
        let der = certificate
            .to_der()
            .map_err(|_| Error::CertificateRequest)?;
        digest.update((der.len() as u64).to_be_bytes());
        digest.update(der);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        x509::{
            X509Builder,
            extension::{BasicConstraints, KeyUsage},
        },
    };
    const NOW: i64 = 1_800_000_000;
    fn root() -> (PKey<Private>, X509) {
        let key =
            PKey::private_key_from_pem(include_bytes!("../../tests/fixtures/runtime-root-key.pem"))
                .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Approved test root")
            .unwrap();
        let name = name.build();
        let mut cert = X509Builder::new().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::from_unix(NOW - 60).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::from_unix(NOW + 86400).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        (key, cert.build())
    }
    fn leaf(
        root: &X509,
        signer: &PKey<Private>,
        private: &[u8],
        topic: Option<&str>,
        expires: i64,
    ) -> String {
        let public = PKey::private_key_from_pkcs8(private).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "MDM test leaf").unwrap();
        if let Some(topic) = topic {
            name.append_entry_by_text("UID", topic).unwrap();
        }
        let mut cert = X509Builder::new().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name.build()).unwrap();
        cert.set_issuer_name(root.subject_name()).unwrap();
        cert.set_pubkey(&public).unwrap();
        cert.set_not_before(&Asn1Time::from_unix(NOW - 60).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::from_unix(expires).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
        cert.sign(signer, MessageDigest::sha256()).unwrap();
        String::from_utf8(cert.build().to_pem().unwrap()).unwrap()
    }
    #[test]
    fn generated_csr_and_certificate_bind_the_exact_private_key_and_approved_root() {
        let key = prepare(
            "11111111-1111-4111-8111-111111111111",
            Purpose::Profile,
            None,
        )
        .unwrap();
        let csr = openssl::x509::X509Req::from_pem(key.csr.as_bytes()).unwrap();
        assert!(csr.verify(&csr.public_key().unwrap()).unwrap());
        let (signer, root) = root();
        let roots = vec![root.to_pem().unwrap()];
        let cert = leaf(&root, &signer, &key.private, None, NOW + 3600);
        let validated = certificate(Purpose::Profile, &cert, &key.private, &roots, NOW).unwrap();
        assert_eq!(validated.expires, NOW + 3600);
        let other =
            PKey::private_key_from_pem(include_bytes!("../../tests/fixtures/runtime-root-key.pem"))
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap();
        assert!(certificate(Purpose::Profile, &cert, &other, &roots, NOW).is_err());
        assert!(certificate(Purpose::Profile, &cert, &key.private, &[], NOW).is_err());
        assert!(certificate(Purpose::Profile, &cert, &key.private, &roots, NOW + 3600).is_err());
        assert!(certificate(Purpose::Apns, &cert, &key.private, &roots, NOW).is_err());
    }
    #[test]
    fn candidate_expiry_includes_the_verified_root_and_digest_binds_the_supplied_chain() {
        let private =
            PKey::private_key_from_pem(include_bytes!("../../tests/fixtures/runtime-leaf-key.pem"))
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap();
        let (signer, root) = root();
        let roots = vec![root.to_pem().unwrap()];
        let cert = leaf(&root, &signer, &private, None, NOW + 172800);
        let original = certificate(Purpose::Profile, &cert, &private, &roots, NOW).unwrap();
        assert_eq!(original.expires, NOW + 86400);
        let with_chain = format!(
            "{cert}{}",
            String::from_utf8(root.to_pem().unwrap()).unwrap()
        );
        let changed = certificate(Purpose::Profile, &with_chain, &private, &roots, NOW).unwrap();
        assert_ne!(original.digest, changed.digest);
    }
    #[test]
    fn persisted_identity_rejects_corruption_without_confusing_expiry_with_integrity() {
        let private =
            PKey::private_key_from_pem(include_bytes!("../../tests/fixtures/runtime-leaf-key.pem"))
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap();
        let (signer, root) = root();
        let cert = leaf(&root, &signer, &private, None, NOW + 60);
        let digest = persisted_digest(&cert, &private).unwrap();
        assert_eq!(
            digest,
            certificate(
                Purpose::Profile,
                &cert,
                &private,
                &[root.to_pem().unwrap()],
                NOW
            )
            .unwrap()
            .digest
        );
        assert!(
            certificate(
                Purpose::Profile,
                &cert,
                &private,
                &[root.to_pem().unwrap()],
                NOW + 60
            )
            .is_err()
        );
        assert_eq!(persisted_digest(&cert, &private).unwrap(), digest);
        assert!(persisted_digest("corrupt persisted PEM", &private).is_err());
        let other =
            PKey::private_key_from_pem(include_bytes!("../../tests/fixtures/runtime-root-key.pem"))
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap();
        assert!(persisted_digest(&cert, &other).is_err());
    }
    #[test]
    fn apns_requires_one_mdm_topic_and_ca_private_material_is_never_a_leaf() {
        let private =
            PKey::private_key_from_pem(include_bytes!("../../tests/fixtures/runtime-leaf-key.pem"))
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap();
        let (signer, root) = root();
        let roots = vec![root.to_pem().unwrap()];
        let cert = leaf(
            &root,
            &signer,
            &private,
            Some("com.apple.mgmt.tenant"),
            NOW + 3600,
        );
        assert_eq!(
            certificate(Purpose::Apns, &cert, &private, &roots, NOW)
                .unwrap()
                .topic
                .as_deref(),
            Some("com.apple.mgmt.tenant")
        );
        let wrong = leaf(
            &root,
            &signer,
            &private,
            Some("ordinary.client"),
            NOW + 3600,
        );
        assert!(certificate(Purpose::Apns, &wrong, &private, &roots, NOW).is_err());
        let root_pem = String::from_utf8(root.to_pem().unwrap()).unwrap();
        assert!(
            certificate(
                Purpose::Profile,
                &root_pem,
                &signer.private_key_to_pkcs8().unwrap(),
                &roots,
                NOW
            )
            .is_err()
        );
    }
}
