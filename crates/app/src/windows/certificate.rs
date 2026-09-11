//! ref: RustCrypto formats x509-cert/v0.2.5 src/request.rs; ring 0.17.14 src/rsa/keypair.rs.
use crate::{ConfigIssue, Error, Failure, config};
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
    Certificate, TbsCertificate, Version,
    der::{
        self, Decode, DecodePem, Encode,
        asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, UtcTime},
    },
    ext::{
        AsExtension,
        pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages},
    },
    name::Name,
    request::CertReq,
    serial_number::SerialNumber,
    spki::AlgorithmIdentifierOwned,
    time::{Time, Validity},
};
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::Malformed
}
fn signature_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: SHA256_RSA,
        parameters: Some(Any::null()),
    }
}
fn rsa_algorithm(algorithm: &AlgorithmIdentifierOwned, oid: ObjectIdentifier) -> bool {
    algorithm.oid == oid
        && algorithm
            .parameters
            .as_ref()
            .is_none_or(|p| p == &Any::null())
}
pub(super) struct Csr {
    info: x509_cert::request::CertReqInfo,
}
impl Csr {
    pub(super) fn verify(bytes: &[u8]) -> Result<Self, Error> {
        Self::verify_der(bytes).map_err(|_| Error::CertificateRequest)
    }
    fn verify_der(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 32768 {
            return Err(Error::Malformed);
        }
        let csr = CertReq::from_der(bytes).map_err(invalid)?;
        if csr.to_der().map_err(invalid)? != bytes
            || !rsa_algorithm(&csr.algorithm, SHA256_RSA)
            || !rsa_algorithm(&csr.info.public_key.algorithm, RSA)
        {
            return Err(Error::Malformed);
        }
        signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            csr.info
                .public_key
                .subject_public_key
                .as_bytes()
                .ok_or(Error::Malformed)?,
        )
        .verify(
            &csr.info.to_der().map_err(invalid)?,
            csr.signature.as_bytes().ok_or(Error::Malformed)?,
        )
        .map_err(invalid)?;
        Ok(Self { info: csr.info })
    }
}
/// Constructed only after cryptographic chain and explicit leaf-purpose validation.
pub(crate) struct CheckedLeaf {
    fingerprint: [u8; 32],
}
impl CheckedLeaf {
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
pub(super) struct Ca {
    key: signature::RsaKeyPair,
    certificate: Certificate,
    pub(super) der: Vec<u8>,
    pub(super) verifier: Arc<dyn ClientCertVerifier>,
}
impl Ca {
    pub(super) fn load(certificate: &Path, key: &Path, now: i64) -> Result<Self, Error> {
        Self::from_bytes(
            &config::read(certificate, 32768, false)?,
            &config::read(key, 32768, true)?,
            now,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))
    }
    fn from_bytes(pem: &[u8], pkcs8: &[u8], now: i64) -> Result<Self, Error> {
        let certificate = Certificate::from_pem(pem).map_err(invalid)?;
        let der = certificate.to_der().map_err(invalid)?;
        let key = signature::RsaKeyPair::from_pkcs8(pkcs8).map_err(invalid)?;
        let tbs = &certificate.tbs_certificate;
        let bc = tbs
            .get::<BasicConstraints>()
            .map_err(invalid)?
            .ok_or(Error::Malformed)?
            .1;
        let ku = tbs
            .get::<KeyUsage>()
            .map_err(invalid)?
            .ok_or(Error::Malformed)?
            .1;
        if !bc.ca
            || !ku.key_cert_sign()
            || !valid_at(tbs, now)
            || tbs.subject != tbs.issuer
            || !rsa_algorithm(&tbs.subject_public_key_info.algorithm, RSA)
            || tbs.subject_public_key_info.subject_public_key.as_bytes()
                != Some(key.public_key().as_ref())
        {
            return Err(Error::Malformed);
        }
        let mut probe = vec![0; key.public().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            b"mdm.ca.key-match.v1",
            &mut probe,
        )
        .map_err(invalid)?;
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key.public_key())
            .verify(b"mdm.ca.key-match.v1", &probe)
            .map_err(invalid)?;
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
            key,
            certificate,
            der,
            verifier,
        })
    }
    pub(super) fn intent(&self, csr: &Csr, registration: Uuid, now: i64) -> Result<Vec<u8>, Error> {
        if !valid_at(&self.certificate.tbs_certificate, now) {
            return Err(Error::Unavailable(Failure::Certificate));
        }
        let subject: Name = format!("CN={registration}").parse().map_err(invalid)?;
        let extensions = vec![
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(&subject, &[])
            .map_err(invalid)?,
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_extension(&subject, &[])
                .map_err(invalid)?,
            ExtendedKeyUsage(vec![CLIENT_AUTH])
                .to_extension(&subject, &[])
                .map_err(invalid)?,
        ];
        let expiry = (now as u64 + 90 * 86400).min(
            self.certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        );
        let serial = Uuid::new_v4();
        let mut serial = *serial.as_bytes();
        serial[0] &= 0x7f;
        TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&serial).map_err(invalid)?,
            signature: signature_algorithm(),
            issuer: self.certificate.tbs_certificate.subject.clone(),
            validity: Validity {
                not_before: timestamp(now as u64)?,
                not_after: timestamp(expiry)?,
            },
            subject,
            subject_public_key_info: csr.info.public_key.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        }
        .to_der()
        .map_err(invalid)
    }
    pub(super) fn sign(&self, intent: &[u8]) -> Result<Vec<u8>, Error> {
        let tbs = TbsCertificate::from_der(intent).map_err(invalid)?;
        if tbs.to_der().map_err(invalid)? != intent
            || tbs.issuer != self.certificate.tbs_certificate.subject
            || tbs.signature != signature_algorithm()
        {
            return Err(Error::Conflict);
        }
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                intent,
                &mut signature,
            )
            .map_err(|_| Error::Unavailable(Failure::Certificate))?;
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: signature_algorithm(),
            signature: BitString::from_bytes(&signature).map_err(invalid)?,
        }
        .to_der()
        .map_err(invalid)
    }
    pub(super) fn verify(
        &self,
        chain: &[CertificateDer<'_>],
        now: i64,
    ) -> Result<CheckedLeaf, Error> {
        if chain.is_empty()
            || chain.len() > 4
            || chain.iter().any(|c| c.len() > 32768)
            || now <= 0
            || !valid_at(&self.certificate.tbs_certificate, now)
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
        let certificate = Certificate::from_der(&chain[0]).map_err(|_| Error::Unauthorized)?;
        leaf_usage(&certificate.tbs_certificate, now).map_err(|_| Error::Unauthorized)?;
        Ok(CheckedLeaf {
            fingerprint: Sha256::digest(&chain[0]).into(),
        })
    }
}
pub(crate) fn leaf_usage(tbs: &TbsCertificate, now: i64) -> Result<(), Error> {
    let bc = tbs
        .get::<BasicConstraints>()
        .map_err(invalid)?
        .ok_or(Error::Malformed)?
        .1;
    let ku = tbs
        .get::<KeyUsage>()
        .map_err(invalid)?
        .ok_or(Error::Malformed)?
        .1;
    let eku = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(invalid)?
        .ok_or(Error::Malformed)?
        .1;
    if bc.ca
        || !ku.digital_signature()
        || ku.key_cert_sign()
        || !eku.0.contains(&CLIENT_AUTH)
        || !valid_at(tbs, now)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
fn valid_at(tbs: &TbsCertificate, now: i64) -> bool {
    now > 0
        && tbs.validity.not_before.to_unix_duration().as_secs() <= now as u64
        && (now as u64) < tbs.validity.not_after.to_unix_duration().as_secs()
}
fn timestamp(seconds: u64) -> Result<Time, Error> {
    let date = der::DateTime::from_unix_duration(Duration::from_secs(seconds)).map_err(invalid)?;
    if date.year() <= 2049 {
        Ok(UtcTime::from_date_time(date).map_err(invalid)?.into())
    } else {
        Ok(GeneralizedTime::from_date_time(date).into())
    }
}
