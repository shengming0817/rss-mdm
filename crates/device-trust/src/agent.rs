//! Agent trust generations and authorized issuance evidence.
use rss_mdm_certificate::{
    Error, HandshakePeer,
    agent::{PROFILE, VerifiedAgentCsr},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::rustls::{pki_types::CertificateDer, server::danger::ClientCertVerifier};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};
fn malformed(_: impl std::fmt::Debug) -> Error {
    Error::Malformed
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Metadata {
    pub profile: &'static str,
    pub identity: String,
    pub issuer: [u8; 32],
    pub fingerprint: [u8; 32],
    pub spki: [u8; 32],
    pub serial: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub provisioner: String,
}
/// Validated issuance output. This type is not channel credential evidence.
pub struct IssuedAgentCertificate {
    pub metadata: Metadata,
    pub csr_digest: [u8; 32],
    pub chain: Vec<Vec<u8>>,
}
/// Can only be constructed from completed TLS, never HTTP certificate text.
pub struct VerifiedAgentPeer {
    metadata: Metadata,
}
impl VerifiedAgentPeer {
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}
pub struct AgentTrust {
    pub trust: crate::DeviceTrust,
    max_seconds: i64,
}
fn valid(c: &Certificate, now: i64) -> bool {
    now > 0
        && c.tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs()
            <= now as u64
        && (now as u64)
            < c.tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
}
impl AgentTrust {
    pub fn from_trust(trust: crate::DeviceTrust, max_days: u16) -> Result<Self, Error> {
        let active = trust.active()?;
        if active.provisioner != "rss-agent"
            || active.kid.is_empty()
            || active.kid.len() > 128
            || !(1..=3650).contains(&max_days)
        {
            return Err(Error::Malformed);
        }
        let der = crate::decode(&active.certificate, 32768)?;
        let issuer = Certificate::from_der(&der).map_err(malformed)?;
        let _ = issuer;
        Ok(Self {
            trust,
            max_seconds: i64::from(max_days) * 86400,
        })
    }
    /// Offer real client authentication while permitting anonymous bootstrap requests.
    pub fn enrollment_verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.trust.verifier(true)
    }
    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.trust.verifier(false)
    }
    pub fn issuer_digest(&self) -> [u8; 32] {
        self.trust
            .active()
            .and_then(|g| crate::decode(&g.certificate, 32768))
            .map(|der| Sha256::digest(der).into())
            .unwrap_or([0; 32])
    }
    fn active_certificate(&self) -> Result<Certificate, Error> {
        Certificate::from_der(&crate::decode(&self.trust.active()?.certificate, 32768)?)
            .map_err(malformed)
    }
    pub fn expires(&self) -> i64 {
        self.active_certificate()
            .map(|c| {
                c.tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs() as i64
            })
            .unwrap_or(0)
    }
    pub fn permits_window(&self, start: i64, end: i64) -> bool {
        self.active_certificate().is_ok_and(|c| {
            start > 0
                && valid(&c, start)
                && end > start
                && end <= self.expires()
                && end - start <= self.max_seconds
        })
    }
    fn check(&self, chain: &[CertificateDer<'_>], now: i64) -> Result<Metadata, Error> {
        let generation = self.trust.verify(chain, now)?;
        self.metadata(&chain[0], generation)
    }
    fn metadata(
        &self,
        der: &[u8],
        generation: rss_mdm_agent_wire::pki::Issuer,
    ) -> Result<Metadata, Error> {
        let issuer_bytes = crate::decode(&generation.certificate, 32768)?;
        let issuer = Certificate::from_der(&issuer_bytes).map_err(malformed)?;
        let c = Certificate::from_der(der).map_err(malformed)?;
        let t = &c.tbs_certificate;
        let start = t.validity.not_before.to_unix_duration().as_secs() as i64;
        let end = t.validity.not_after.to_unix_duration().as_secs() as i64;
        rss_mdm_certificate::agent::validate_leaf_profile(&c, &issuer, self.max_seconds)?;
        let identity = crate::agent_identity(&c, &generation)?;
        Ok(Metadata {
            profile: PROFILE,
            identity,
            issuer: Sha256::digest(&issuer_bytes).into(),
            fingerprint: Sha256::digest(der).into(),
            spki: Sha256::digest(t.subject_public_key_info.to_der().map_err(malformed)?).into(),
            serial: t.serial_number.as_bytes().to_vec(),
            not_before: start,
            not_after: end,
            provisioner: generation.provisioner,
        })
    }
    pub fn validate_issued(
        &self,
        chain: Vec<Vec<u8>>,
        csr: &VerifiedAgentCsr,
        identity: &str,
        start: i64,
        end: i64,
        now: i64,
    ) -> Result<IssuedAgentCertificate, Error> {
        self.validate_issued_for(self.issuer_digest(), chain, csr, identity, start..end, now)
    }
    pub fn validate_issued_for(
        &self,
        expected_issuer: [u8; 32],
        chain: Vec<Vec<u8>>,
        csr: &VerifiedAgentCsr,
        identity: &str,
        validity: std::ops::Range<i64>,
        now: i64,
    ) -> Result<IssuedAgentCertificate, Error> {
        let refs = chain
            .iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect::<Vec<_>>();
        let metadata = self.check(&refs, now)?;
        if metadata.issuer != expected_issuer
            || metadata.identity != identity
            || metadata.spki != csr.spki()
            || metadata.not_before != validity.start
            || metadata.not_after != validity.end
        {
            return Err(Error::Conflict);
        }
        Ok(IssuedAgentCertificate {
            metadata,
            csr_digest: csr.digest(),
            chain,
        })
    }
    /// Resolve the original issued result, including an expired or revoked candidate.
    /// The activation owner still requires a fresh live certificate and current authorization.
    pub fn recover_issued_for(
        &self,
        expected_issuer: [u8; 32],
        chain: Vec<Vec<u8>>,
        csr: &VerifiedAgentCsr,
        identity: &str,
        start: i64,
        end: i64,
    ) -> Result<IssuedAgentCertificate, Error> {
        if chain.is_empty() || chain.len() > 4 || chain.iter().any(|c| c.len() > 32768) {
            return Err(Error::Malformed);
        }
        let issuer = expected_issuer
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let generation = self.trust.verify_history(&chain[0], &issuer)?;
        let metadata = self.metadata(&chain[0], generation)?;
        if metadata.identity != identity
            || metadata.spki != csr.spki()
            || metadata.not_before != start
            || metadata.not_after != end
        {
            return Err(Error::Conflict);
        }
        Ok(IssuedAgentCertificate {
            metadata,
            csr_digest: csr.digest(),
            chain,
        })
    }
    pub fn verify_peer(&self, peer: &HandshakePeer, now: i64) -> Result<VerifiedAgentPeer, Error> {
        self.check(peer.chain(), now)
            .map(|metadata| VerifiedAgentPeer { metadata })
    }
}
