//! Typed CMS encoding and rustls/ring verification; no runtime shell or home-grown crypto.
//! ref: RustCrypto/formats cms-0.2.3 src/signed_data.rs; ring-0.17.14 src/rsa/keypair.rs
mod account;
use crate::Error;
pub use account::{EnrollmentRequest, ManagedAccountTokenSigner, enrollment_request};
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
use tokio_rustls::rustls::{self, pki_types::CertificateDer};
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{
        Decode, Encode,
        asn1::{Any, ObjectIdentifier, OctetString, SetOfVec},
    },
    request::CertReq,
    spki::AlgorithmIdentifierOwned,
};
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::CertificateRequest
}
pub fn valid(c: &Certificate, now: i64) -> bool {
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
        let certificates = CertificateDer::pem_slice_iter(bytes)
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

pub fn subject(enrollment: Uuid, attempt: Uuid) -> String {
    // X.509 commonName is limited to 64 characters. Both UUIDs retain all 128 bits.
    format!("{}{}", enrollment.simple(), attempt.simple())
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
    let (enrollment, attempt) = parse_subject(&c.info.subject)?;
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

pub mod ade;

pub fn parse_subject(name: &x509_cert::name::Name) -> Result<(uuid::Uuid, uuid::Uuid), Error> {
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
    let enrollment = uuid::Uuid::parse_str(&value[..32]).map_err(invalid)?;
    let attempt = uuid::Uuid::parse_str(&value[32..]).map_err(invalid)?;
    if enrollment.is_nil() || attempt.is_nil() {
        return Err(Error::Unauthorized);
    }
    Ok((enrollment, attempt))
}
