//! Windows CSR and device trust validation. No certificate signing key is held here.
//! ref: RustCrypto formats x509-cert/v0.2.5 src/request.rs; rustls client_verifier.rs.
mod linked;
mod renewal;
use crate::Error;
pub use linked::LinkedProof;
pub use renewal::RenewalProof;
use ring::signature;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::rustls::{pki_types::CertificateDer, server::danger::ClientCertVerifier};
use uuid::Uuid;
use x509_cert::{
    Certificate, TbsCertificate,
    der::{
        Decode, Encode, EncodePem,
        asn1::{Any, ObjectIdentifier},
    },
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    request::CertReq,
    spki::AlgorithmIdentifierOwned,
};
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::Malformed
}
fn rsa_algorithm(algorithm: &AlgorithmIdentifierOwned, oid: ObjectIdentifier) -> bool {
    algorithm.oid == oid
        && algorithm
            .parameters
            .as_ref()
            .is_none_or(|p| p == &Any::null())
}
pub struct Csr {
    info: x509_cert::request::CertReqInfo,
    der: Vec<u8>,
}
impl Csr {
    pub fn verify(bytes: &[u8]) -> Result<Self, Error> {
        Self::verify_der(bytes).map_err(|_| Error::CertificateRequest)
    }
    pub fn pem(&self) -> Result<String, Error> {
        CertReq::from_der(&self.der)
            .map_err(invalid)?
            .to_pem(x509_cert::der::pem::LineEnding::LF)
            .map_err(invalid)
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.der).into()
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
        Ok(Self {
            info: csr.info,
            der: bytes.to_vec(),
        })
    }
}
/// Constructed only after cryptographic chain and explicit leaf-purpose validation.
pub struct CheckedLeaf {
    fingerprint: [u8; 32],
}
impl CheckedLeaf {
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
pub struct WindowsDeviceTrust {
    pub trust: rss_mdm_device_trust::DeviceTrust,
}
impl WindowsDeviceTrust {
    pub fn der(&self) -> Result<Vec<u8>, Error> {
        Ok(rss_mdm_device_trust::decode(
            &self.trust.active()?.certificate,
            32768,
        )?)
    }
    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.trust.verifier(false)
    }

    /// Enrollment permits unauthenticated initial enrollment, but verifies any offered TLS identity.
    pub fn enrollment_verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.trust.verifier(true)
    }
    pub fn from_trust(trust: rss_mdm_device_trust::DeviceTrust) -> Result<Self, Error> {
        let active = trust.active()?;
        let der = rss_mdm_device_trust::decode(&active.certificate, 32768)?;
        let certificate = Certificate::from_der(&der).map_err(invalid)?;
        let _ = certificate;
        Ok(Self { trust })
    }
    pub fn profile(
        &self,
        csr: &Csr,
        registration: Uuid,
        now: i64,
    ) -> Result<IssuanceProfile, Error> {
        let der = self.der()?;
        let certificate = Certificate::from_der(&der).map_err(invalid)?;
        if !valid_at(&certificate.tbs_certificate, now) {
            return Err(Error::Expired);
        }
        let end = now.checked_add(90 * 86400).ok_or(Error::Malformed)?;
        if end as u64
            > certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
        {
            return Err(Error::Expired);
        }
        Ok(IssuanceProfile {
            version: 1,
            registration,
            start: now,
            end,
            spki: Sha256::digest(csr.info.public_key.to_der().map_err(invalid)?).into(),
            issuer: Sha256::digest(&der).into(),
        })
    }
    /// Validate frozen key, subject, purpose, issuer and validity, independent of CA serial/signature bytes.
    pub fn validate_issued(
        &self,
        profile: &IssuanceProfile,
        csr: &Csr,
        chain: &[CertificateDer<'_>],
        now: i64,
    ) -> Result<CheckedLeaf, Error> {
        let checked = self.verify(chain, now)?;
        let leaf = Certificate::from_der(&chain[0]).map_err(invalid)?;
        let tbs = &leaf.tbs_certificate;
        let subject: x509_cert::name::Name = format!("CN={}", profile.registration)
            .parse()
            .map_err(invalid)?;
        if profile.version != 1
            || profile.issuer
                != Sha256::digest(rss_mdm_device_trust::decode(
                    &self.trust.verify(chain, now)?.certificate,
                    32768,
                )?)
                .as_slice()
            || tbs.subject != subject
            || tbs.subject_public_key_info != csr.info.public_key
            || profile.spki
                != <[u8; 32]>::from(Sha256::digest(
                    csr.info.public_key.to_der().map_err(invalid)?,
                ))
            || tbs.validity.not_before.to_unix_duration().as_secs() != profile.start as u64
            || tbs.validity.not_after.to_unix_duration().as_secs() != profile.end as u64
            || tbs
                .get::<x509_cert::ext::pkix::SubjectAltName>()
                .map_err(invalid)?
                .is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(checked)
    }
    pub fn verify(&self, chain: &[CertificateDer<'_>], now: i64) -> Result<CheckedLeaf, Error> {
        self.trust.verify(chain, now)?;
        let certificate = Certificate::from_der(&chain[0]).map_err(|_| Error::Unauthorized)?;
        leaf_usage(&certificate.tbs_certificate, now).map_err(|_| Error::Unauthorized)?;
        Ok(CheckedLeaf {
            fingerprint: Sha256::digest(&chain[0]).into(),
        })
    }
}
pub fn leaf_usage(tbs: &TbsCertificate, now: i64) -> Result<(), Error> {
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceProfile {
    pub version: u8,
    pub registration: Uuid,
    pub start: i64,
    pub end: i64,
    pub spki: [u8; 32],
    pub issuer: [u8; 32],
}
impl IssuanceProfile {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(invalid)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4096 {
            return Err(Error::Malformed);
        }
        let profile: Self = serde_json::from_slice(bytes).map_err(invalid)?;
        if profile.version != 1
            || profile.start <= 0
            || profile.end <= profile.start
            || profile.end - profile.start > 90 * 86400
        {
            return Err(Error::Malformed);
        }
        Ok(profile)
    }
}
