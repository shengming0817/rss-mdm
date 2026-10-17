//! Apple device trust generations and verified enrollment identity.
use rss_mdm_certificate::{
    Error,
    apple::{parse_subject, valid},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::rustls::{pki_types::CertificateDer, server::danger::ClientCertVerifier};
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{Decode, Encode, asn1::ObjectIdentifier},
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName},
};
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::CertificateRequest
}
pub struct AppleDeviceTrust {
    pub trust: crate::DeviceTrust,
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
            .and_then(|g| crate::decode(&g.certificate, 32768))
            .map(|der| Sha256::digest(der).into())
            .unwrap_or([0; 32])
    }

    pub fn expires(&self) -> u64 {
        self.trust
            .active()
            .and_then(|g| crate::decode(&g.certificate, 32768))
            .and_then(|der| Certificate::from_der(&der).map_err(|_| crate::Error::Malformed))
            .map(|c| {
                c.tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs()
            })
            .unwrap_or(0)
    }
    pub fn from_trust(trust: crate::DeviceTrust) -> Result<Self, Error> {
        let der = crate::decode(&trust.active()?.certificate, 32768)?;
        let issuer = Certificate::from_der(&der).map_err(invalid)?;
        let _ = issuer;
        Ok(Self { trust })
    }
    pub fn verify(&self, chain: &[CertificateDer<'_>], now: i64) -> Result<CheckedLeaf, Error> {
        let generation = self.trust.verify(chain, now)?;
        let issuer = Certificate::from_der(&crate::decode(&generation.certificate, 32768)?)
            .map_err(invalid)?;
        let c = Certificate::from_der(&chain[0]).map_err(invalid)?;
        let tbs = &c.tbs_certificate;
        let (enrollment, attempt) = parse_subject(&tbs.subject)?;
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
            issuer: Sha256::digest(crate::decode(&generation.certificate, 32768)?).into(),
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
