//! Typed CMS encoding and rustls/ring verification; no runtime shell or home-grown crypto.
//! ref: RustCrypto/formats cms-0.2.3 src/signed_data.rs; ring-0.17.14 src/rsa/keypair.rs
use crate::{ConfigIssue, Error, Failure};
use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    },
};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, UnixTime},
    server::danger::ClientCertVerifier,
};
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{
        Decode, DecodePem, Encode,
        asn1::{Any, ObjectIdentifier, OctetString, SetOfVec},
    },
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName},
    name::Name,
    request::CertReq,
    spki::AlgorithmIdentifierOwned,
};
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::CertificateRequest
}
fn valid(c: &Certificate, now: i64) -> bool {
    now > 0
        && c.tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs()
            <= now as u64
        && c.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            > now as u64
}
pub(super) struct Signer {
    key: signature::RsaKeyPair,
    certificates: Vec<Certificate>,
}
impl Signer {
    pub(super) fn load(cert: &Path, key: &Path, now: i64) -> Result<Self, Error> {
        use rustls::pki_types::pem::PemObject;
        let bytes = crate::config::read(cert, 128 * 1024, false)?;
        let certificates = CertificateDer::pem_slice_iter(&bytes)
            .map(|c| Certificate::from_der(&c.map_err(invalid)?).map_err(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        let key = signature::RsaKeyPair::from_pkcs8(&crate::config::read(key, 32768, true)?)
            .map_err(invalid)?;
        let leaf = certificates
            .first()
            .ok_or(Error::Configuration(ConfigIssue::Apple))?;
        if certificates.len() > 4
            || !valid(leaf, now)
            || leaf.tbs_certificate.subject_public_key_info.algorithm.oid != RSA
            || leaf
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                != Some(key.public_key().as_ref())
        {
            return Err(Error::Configuration(ConfigIssue::Apple));
        }
        Ok(Self { key, certificates })
    }
    pub(super) fn sign(&self, bytes: &[u8], now: i64) -> Result<Vec<u8>, Error> {
        let certificate = &self.certificates[0];
        if !valid(certificate, now) {
            return Err(Error::Unavailable(Failure::Certificate));
        }
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                bytes,
                &mut signature,
            )
            .map_err(invalid)?;
        let digest = AlgorithmIdentifierOwned {
            oid: SHA256,
            parameters: None,
        };
        let signed = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::try_from(vec![digest.clone()]).map_err(invalid)?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1"),
                econtent: Some(
                    Any::encode_from(&OctetString::new(bytes).map_err(invalid)?)
                        .map_err(invalid)?,
                ),
            },
            certificates: Some(
                CertificateSet::try_from(
                    self.certificates
                        .iter()
                        .cloned()
                        .map(CertificateChoices::Certificate)
                        .collect::<Vec<_>>(),
                )
                .map_err(invalid)?,
            ),
            crls: None,
            signer_infos: SignerInfos::try_from(vec![SignerInfo {
                version: CmsVersion::V1,
                sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                    issuer: certificate.tbs_certificate.issuer.clone(),
                    serial_number: certificate.tbs_certificate.serial_number.clone(),
                }),
                digest_alg: digest,
                signed_attrs: None,
                signature_algorithm: AlgorithmIdentifierOwned {
                    oid: RSA,
                    parameters: Some(Any::null()),
                },
                signature: OctetString::new(signature).map_err(invalid)?,
                unsigned_attrs: None,
            }])
            .map_err(invalid)?,
        };
        ContentInfo {
            content_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2"),
            content: Any::encode_from(&signed).map_err(invalid)?,
        }
        .to_der()
        .map_err(invalid)
    }
}
pub(super) struct Authority {
    pub verifier: Arc<dyn ClientCertVerifier>,
    issuer: Certificate,
    pub issuer_fingerprint: [u8; 32],
}
pub(crate) struct CheckedLeaf {
    pub(super) fingerprint: [u8; 32],
    pub(super) spki: [u8; 32],
    pub(super) enrollment: Uuid,
    pub(super) attempt: Uuid,
    pub(super) serial: Vec<u8>,
    pub(super) certificate: Vec<u8>,
}
impl CheckedLeaf {
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
impl Authority {
    pub(super) fn load(path: &Path, now: i64) -> Result<Self, Error> {
        let issuer =
            Certificate::from_pem(&crate::config::read(path, 32768, false)?).map_err(invalid)?;
        if !valid(&issuer, now)
            || issuer
                .tbs_certificate
                .get::<BasicConstraints>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| !v.ca)
            || issuer
                .tbs_certificate
                .get::<KeyUsage>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| !v.key_cert_sign())
        {
            return Err(Error::Configuration(ConfigIssue::Apple));
        }
        let der = issuer.to_der().map_err(invalid)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(invalid)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(invalid)?;
        Ok(Self {
            verifier,
            issuer,
            issuer_fingerprint: Sha256::digest(der).into(),
        })
    }
    pub(super) fn verify(
        &self,
        chain: &[CertificateDer<'_>],
        now: i64,
    ) -> Result<CheckedLeaf, Error> {
        if chain.is_empty()
            || chain.len() > 4
            || chain.iter().any(|c| c.len() > 32768)
            || !valid(&self.issuer, now)
        {
            return Err(Error::Unauthorized);
        }
        self.verifier
            .verify_client_cert(
                &chain[0],
                &chain[1..],
                UnixTime::since_unix_epoch(Duration::from_secs(now as u64)),
            )
            .map_err(|_| Error::Unauthorized)?;
        let c = Certificate::from_der(&chain[0]).map_err(invalid)?;
        let tbs = &c.tbs_certificate;
        let (enrollment, attempt) = subject_ids(&tbs.subject)?;
        if !valid(&c, now)
            || tbs
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
                .saturating_sub(tbs.validity.not_before.to_unix_duration().as_secs())
                > 90 * 86400
            || tbs.issuer != self.issuer.tbs_certificate.subject
            || tbs
                .get::<BasicConstraints>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| v.ca)
            || tbs
                .get::<KeyUsage>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| !v.digital_signature() || v.key_cert_sign())
            || tbs
                .get::<ExtendedKeyUsage>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| v.0 != vec![CLIENT_AUTH])
            || tbs.get::<SubjectAltName>().map_err(invalid)?.is_some()
        {
            return Err(Error::Unauthorized);
        }
        Ok(CheckedLeaf {
            fingerprint: Sha256::digest(&chain[0]).into(),
            spki: Sha256::digest(tbs.subject_public_key_info.to_der().map_err(invalid)?).into(),
            enrollment,
            attempt,
            serial: tbs.serial_number.as_bytes().to_vec(),
            certificate: chain[0].to_vec(),
        })
    }
}
pub(super) fn subject(enrollment: Uuid, attempt: Uuid) -> String {
    // X.509 commonName is limited to 64 characters. Both UUIDs retain all 128 bits.
    format!("{}{}", enrollment.simple(), attempt.simple())
}
fn subject_ids(name: &Name) -> Result<(Uuid, Uuid), Error> {
    use x509_cert::der::Tagged;
    if name.0.len() != 1 || name.0[0].0.len() != 1 {
        return Err(Error::Unauthorized);
    }
    let attribute = name.0[0].0.iter().next().ok_or(Error::Unauthorized)?;
    if attribute.oid != ObjectIdentifier::new_unwrap("2.5.4.3")
        || !matches!(
            attribute.value.tag(),
            x509_cert::der::Tag::Utf8String | x509_cert::der::Tag::PrintableString
        )
    {
        return Err(Error::Unauthorized);
    }
    let value = std::str::from_utf8(attribute.value.value()).map_err(invalid)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(Error::Unauthorized);
    }
    let enrollment = Uuid::parse_str(&value[..32]).map_err(invalid)?;
    let attempt = Uuid::parse_str(&value[32..]).map_err(invalid)?;
    if enrollment.is_nil() || attempt.is_nil() {
        return Err(Error::Unauthorized);
    }
    Ok((enrollment, attempt))
}
pub(super) struct Csr {
    pub enrollment: Uuid,
    pub attempt: Uuid,
    pub spki: [u8; 32],
    pub digest: [u8; 32],
}
pub(super) fn csr(bytes: &[u8]) -> Result<Csr, Error> {
    if bytes.len() > 32768 {
        return Err(Error::CertificateRequest);
    }
    let c = CertReq::from_der(bytes).map_err(invalid)?;
    if c.to_der().map_err(invalid)? != bytes
        || c.algorithm.oid != SHA256_RSA
        || c.info.public_key.algorithm.oid != RSA
    {
        return Err(Error::CertificateRequest);
    }
    signature::UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        c.info
            .public_key
            .subject_public_key
            .as_bytes()
            .ok_or(Error::CertificateRequest)?,
    )
    .verify(
        &c.info.to_der().map_err(invalid)?,
        c.signature.as_bytes().ok_or(Error::CertificateRequest)?,
    )
    .map_err(invalid)?;
    let (enrollment, attempt) = subject_ids(&c.info.subject)?;
    Ok(Csr {
        enrollment,
        attempt,
        spki: Sha256::digest(c.info.public_key.to_der().map_err(invalid)?).into(),
        digest: Sha256::digest(bytes).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subject_preserves_two_complete_ids_within_common_name_limit() {
        let enrollment = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let encoded = subject(enrollment, attempt);
        assert_eq!(encoded.len(), 64);
        let name = format!("CN={encoded}").parse().unwrap();
        assert_eq!(subject_ids(&name).unwrap(), (enrollment, attempt));
        assert!(subject_ids(&format!("CN={enrollment}:{attempt}").parse().unwrap()).is_err());
        assert!(subject_ids(&format!("CN={encoded},O=extra").parse().unwrap()).is_err());
        assert!(
            subject_ids(
                &format!("CN={}", subject(Uuid::nil(), attempt))
                    .parse()
                    .unwrap()
            )
            .is_err()
        );
    }
    #[test]
    #[ignore = "Apple T2: disposable real keys and independent OpenSSL CMS verifier"]
    fn cms_is_attached_and_independently_verified() -> anyhow::Result<()> {
        let root = std::path::PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        let signer = Signer::load(
            &root.join("apple-profile.pem"),
            &root.join("apple-profile.pk8"),
            now,
        )?;
        let bytes = super::super::profile::firewall("com.rss.test", Uuid::new_v4(), true)?;
        let cms = signer.sign(&bytes, now)?;
        let work = tempfile::tempdir()?;
        let input = work.path().join("profile.cms");
        let output = work.path().join("profile.plist");
        std::fs::write(&input, &cms)?;
        let status = std::process::Command::new("openssl")
            .args(["cms", "-verify", "-inform", "DER", "-in"])
            .arg(&input)
            .arg("-CAfile")
            .arg(root.join("apple-root.pem"))
            .arg("-out")
            .arg(&output)
            .output()?;
        anyhow::ensure!(
            status.status.success(),
            "independent CMS verification failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        anyhow::ensure!(std::fs::read(&output)? == bytes);
        let mut changed = cms;
        let i = changed.len() - 1;
        changed[i] ^= 1;
        std::fs::write(&input, changed)?;
        anyhow::ensure!(
            !std::process::Command::new("openssl")
                .args(["cms", "-verify", "-inform", "DER", "-in"])
                .arg(&input)
                .arg("-CAfile")
                .arg(root.join("apple-root.pem"))
                .arg("-out")
                .arg(&output)
                .output()?
                .status
                .success()
        );
        Ok(())
    }
}
