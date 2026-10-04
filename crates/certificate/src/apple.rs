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
use std::sync::Arc;
use tokio_rustls::rustls::{self, pki_types::CertificateDer, server::danger::ClientCertVerifier};
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{
        Decode, Encode,
        asn1::{Any, ObjectIdentifier, OctetString, SetOfVec},
    },
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName},
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
pub struct AppleDeviceTrust {
    pub trust: rss_mdm_device_trust::DeviceTrust,
}
pub struct CheckedLeaf {
    issuer: [u8; 32],
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
    pub fn issuer(&self) -> [u8; 32] {
        self.issuer
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
impl AppleDeviceTrust {
    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.trust.verifier(false)
    }
    pub fn issuer_fingerprint(&self) -> [u8; 32] {
        self.trust
            .active()
            .and_then(|g| rss_mdm_device_trust::decode(&g.certificate, 32768))
            .map(|der| Sha256::digest(der).into())
            .unwrap_or([0; 32])
    }

    pub fn expires(&self) -> u64 {
        self.trust
            .active()
            .and_then(|g| rss_mdm_device_trust::decode(&g.certificate, 32768))
            .and_then(|der| {
                Certificate::from_der(&der).map_err(|_| rss_mdm_device_trust::Error::Malformed)
            })
            .map(|c| {
                c.tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs()
            })
            .unwrap_or(0)
    }
    pub fn from_trust(trust: rss_mdm_device_trust::DeviceTrust) -> Result<Self, Error> {
        let der = rss_mdm_device_trust::decode(&trust.active()?.certificate, 32768)?;
        let issuer = Certificate::from_der(&der).map_err(invalid)?;
        let _ = issuer;
        Ok(Self { trust })
    }
    pub fn verify(&self, chain: &[CertificateDer<'_>], now: i64) -> Result<CheckedLeaf, Error> {
        let generation = self.trust.verify(chain, now)?;
        let issuer = Certificate::from_der(&rss_mdm_device_trust::decode(
            &generation.certificate,
            32768,
        )?)
        .map_err(invalid)?;
        let c = Certificate::from_der(&chain[0]).map_err(invalid)?;
        let tbs = &c.tbs_certificate;
        let (enrollment, attempt) = rss_mdm_device_trust::apple_subject(&tbs.subject)?;
        if !valid(&c, now)
            || tbs
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
                .saturating_sub(tbs.validity.not_before.to_unix_duration().as_secs())
                > 90 * 86400
            || tbs.issuer != issuer.tbs_certificate.subject
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
            issuer: Sha256::digest(rss_mdm_device_trust::decode(
                &generation.certificate,
                32768,
            )?)
            .into(),
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
    let (enrollment, attempt) = rss_mdm_device_trust::apple_subject(&c.info.subject)?;
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
