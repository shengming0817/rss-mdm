//! Windows device trust and issuance/renewal verification.
mod linked;
mod renewal;
pub use linked::LinkedProof;
pub use renewal::RenewalProof;
use ring::signature;
use rss_mdm_certificate::{
    Error,
    windows::{Csr, IssuanceProfile, Lifetime, leaf_usage, rsa_algorithm, valid_at},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::rustls::{pki_types::CertificateDer, server::danger::ClientCertVerifier};
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{Decode, Encode, asn1::ObjectIdentifier},
};
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::Malformed
}
pub struct CheckedLeaf {
    fingerprint: [u8; 32],
}
impl CheckedLeaf {
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
pub struct WindowsDeviceTrust {
    lifetime: Lifetime,
    pub trust: crate::DeviceTrust,
}
impl WindowsDeviceTrust {
    pub fn der(&self) -> Result<Vec<u8>, Error> {
        Ok(crate::decode(&self.trust.active()?.certificate, 32768)?)
    }
    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.trust.verifier(false)
    }

    /// Enrollment permits unauthenticated initial enrollment, but verifies any offered TLS identity.
    pub fn enrollment_verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.trust.verifier(true)
    }
    pub fn from_trust(trust: crate::DeviceTrust) -> Result<Self, Error> {
        let active = trust.active()?;
        let der = crate::decode(&active.certificate, 32768)?;
        let certificate = Certificate::from_der(&der).map_err(invalid)?;
        let _ = certificate;
        Ok(Self {
            trust,
            lifetime: Lifetime::Production,
        })
    }
    pub fn with_lifetime(mut self, lifetime: Lifetime) -> Result<Self, Error> {
        lifetime.seconds()?;
        self.lifetime = lifetime;
        Ok(self)
    }
    /// Validate the actual configured device certificate window for readiness and issuance.
    pub fn issuance_end(&self, now: i64) -> Result<i64, Error> {
        let der = self.der()?;
        let certificate = Certificate::from_der(&der).map_err(invalid)?;
        if !valid_at(&certificate.tbs_certificate, now) {
            return Err(Error::Expired);
        }
        let end = now
            .checked_add(self.lifetime.seconds()?)
            .ok_or(Error::Malformed)?;
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
        Ok(end)
    }
    pub fn profile(
        &self,
        csr: &Csr,
        registration: Uuid,
        now: i64,
    ) -> Result<IssuanceProfile, Error> {
        let end = self.issuance_end(now)?;
        Ok(IssuanceProfile {
            version: 1,
            registration,
            start: now,
            end,
            spki: Sha256::digest(csr.public_key().to_der().map_err(invalid)?).into(),
            issuer: Sha256::digest(self.der()?).into(),
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
        // Go's CA encodes an ASCII UUID CN as PrintableString; Rust's Name parser
        // uses UTF8String. The strict Windows leaf profile already rejects extra RDNs.
        // Compare the canonical authorized value rather than a string encoding tag.
        let subject = format!("CN={}", profile.registration);
        if profile.version != 1
            || profile.issuer
                != Sha256::digest(crate::decode(
                    &self.trust.verify(chain, now)?.certificate,
                    32768,
                )?)
                .as_slice()
            || tbs.subject.to_string() != subject
            || tbs.subject_public_key_info != *csr.public_key()
            || profile.spki
                != <[u8; 32]>::from(Sha256::digest(csr.public_key().to_der().map_err(invalid)?))
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
#[cfg(test)]
#[path = "../tests/windows.rs"]
mod tests;
