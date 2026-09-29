//! Typed CMS encoding and rustls/ring verification; no runtime shell or home-grown crypto.
//! ref: RustCrypto/formats cms-0.2.3 src/signed_data.rs; ring-0.17.14 src/rsa/keypair.rs
use crate::Error;
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
use std::{sync::Arc, time::Duration};
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
pub struct ProfileSigner {
    key: signature::RsaKeyPair,
    certificates: Vec<Certificate>,
}
impl ProfileSigner {
    pub fn expires(&self) -> u64 {
        self.certificates[0]
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
    }
    pub fn from_bytes(bytes: &[u8], key: &[u8], now: i64) -> Result<Self, Error> {
        if bytes.len() > 131072 || key.len() > 32768 {
            return Err(Error::Malformed);
        }
        use rustls::pki_types::pem::PemObject;
        let certificates = CertificateDer::pem_slice_iter(&bytes)
            .map(|c| Certificate::from_der(&c.map_err(invalid)?).map_err(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        let key = signature::RsaKeyPair::from_pkcs8(key).map_err(invalid)?;
        let leaf = certificates.first().ok_or(Error::Malformed)?;
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
            return Err(Error::Malformed);
        }
        Ok(Self { key, certificates })
    }
    pub fn sign(&self, bytes: &[u8], now: i64) -> Result<Vec<u8>, Error> {
        let certificate = &self.certificates[0];
        if !valid(certificate, now) {
            return Err(Error::Expired);
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
pub struct AppleDeviceTrust {
    verifier: Arc<dyn ClientCertVerifier>,
    issuer: Certificate,
    issuer_fingerprint: [u8; 32],
}
pub struct CheckedLeaf {
    not_before: i64,
    not_after: i64,
    fingerprint: [u8; 32],
    spki: [u8; 32],
    enrollment: Uuid,
    attempt: Uuid,
    serial: Vec<u8>,
    certificate: Vec<u8>,
}
impl CheckedLeaf {
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
impl AppleDeviceTrust {
    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.verifier.clone()
    }
    pub fn issuer_fingerprint(&self) -> [u8; 32] {
        self.issuer_fingerprint
    }

    pub fn expires(&self) -> u64 {
        self.issuer
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
    }
    pub fn from_bytes(pem: &[u8], now: i64) -> Result<Self, Error> {
        if pem.len() > 131072 {
            return Err(Error::Malformed);
        }
        let issuer = Certificate::from_pem(pem).map_err(invalid)?;
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
            return Err(Error::Malformed);
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
    pub fn verify(&self, chain: &[CertificateDer<'_>], now: i64) -> Result<CheckedLeaf, Error> {
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
            not_before: tbs.validity.not_before.to_unix_duration().as_secs() as i64,
            not_after: tbs.validity.not_after.to_unix_duration().as_secs() as i64,
            fingerprint: Sha256::digest(&chain[0]).into(),
            spki: Sha256::digest(tbs.subject_public_key_info.to_der().map_err(invalid)?).into(),
            enrollment,
            attempt,
            serial: tbs.serial_number.as_bytes().to_vec(),
            certificate: chain[0].to_vec(),
        })
    }
}
pub fn subject(enrollment: Uuid, attempt: Uuid) -> String {
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
pub struct Csr {
    enrollment: Uuid,
    attempt: Uuid,
    spki: [u8; 32],
    digest: [u8; 32],
}
pub fn csr(bytes: &[u8]) -> Result<Csr, Error> {
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
#[path = "../tests/apple.rs"]
mod tests;

impl CheckedLeaf {
    pub fn not_before(&self) -> i64 {
        self.not_before
    }
    pub fn not_after(&self) -> i64 {
        self.not_after
    }
    pub fn spki(&self) -> [u8; 32] {
        self.spki
    }
    pub fn enrollment(&self) -> Uuid {
        self.enrollment
    }
    pub fn attempt(&self) -> Uuid {
        self.attempt
    }
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

impl Csr {
    pub fn enrollment(&self) -> Uuid {
        self.enrollment
    }
    pub fn attempt(&self) -> Uuid {
        self.attempt
    }
    pub fn spki(&self) -> [u8; 32] {
        self.spki
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
