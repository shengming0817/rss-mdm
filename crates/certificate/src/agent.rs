//! Agent-only PKI. Certificate bytes are candidates, never proof of a TLS peer.
//! ref: RustCrypto/formats x509-cert/src/request.rs@x509-cert/v0.2.5;
//! smallstep/certificates authority/provisioner/jwk.go@v0.30.2.
use crate::{Error, HandshakePeer};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::rustls::{pki_types::CertificateDer, server::danger::ClientCertVerifier};
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{
        Decode, Encode,
        asn1::{Any, ObjectIdentifier},
    },
    ext::{
        Extension,
        pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages},
    },
    request::CertReq,
    spki::AlgorithmIdentifierOwned,
};
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const EXTENSION_REQ: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");
pub const SUBJECT: &str = "rss-mdm-agent";
pub const PROFILE: &str = "rss-mdm.agent.v1";
pub const MAX_CSR: usize = 32768;
fn malformed(_: impl std::fmt::Debug) -> Error {
    Error::Malformed
}
fn rsa(algorithm: &AlgorithmIdentifierOwned, oid: ObjectIdentifier) -> bool {
    algorithm.oid == oid
        && algorithm
            .parameters
            .as_ref()
            .is_none_or(|p| p == &Any::null())
}
fn agent_subject(name: &x509_cert::name::Name) -> bool {
    use x509_cert::der::{Tag, Tagged};
    if name.0.len() != 1 || name.0[0].0.len() != 1 {
        return false;
    }
    name.0[0].0.iter().next().is_some_and(|attribute| {
        attribute.oid == COMMON_NAME
            && matches!(
                attribute.value.tag(),
                Tag::Utf8String | Tag::PrintableString
            )
            && attribute.value.value() == SUBJECT.as_bytes()
    })
}
/// Identity comes from the registration owner's authorized database row.
pub fn identity(tenant: Uuid, device: &str) -> Result<String, Error> {
    if tenant.is_nil()
        || device.is_empty()
        || device.len() > 256
        || device.chars().any(char::is_control)
    {
        return Err(Error::Unauthorized);
    }
    Ok(format!(
        "urn:rss-mdm:agent:v1:{tenant}:{}",
        URL_SAFE_NO_PAD.encode(device)
    ))
}
pub struct VerifiedAgentCsr {
    der: Vec<u8>,
    spki: [u8; 32],
    digest: [u8; 32],
}
impl VerifiedAgentCsr {
    pub fn verify(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(bytes).map_err(|_| Error::CertificateRequest)
    }
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_CSR {
            return Err(Error::CertificateRequest);
        }
        let csr = CertReq::from_der(bytes).map_err(malformed)?;
        if csr.to_der().map_err(malformed)? != bytes
            || !rsa(&csr.algorithm, SHA256_RSA)
            || !rsa(&csr.info.public_key.algorithm, RSA)
        {
            return Err(Error::CertificateRequest);
        }
        signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            csr.info
                .public_key
                .subject_public_key
                .as_bytes()
                .ok_or(Error::CertificateRequest)?,
        )
        .verify(
            &csr.info.to_der().map_err(malformed)?,
            csr.signature.as_bytes().ok_or(Error::CertificateRequest)?,
        )
        .map_err(malformed)?;
        if !csr.info.subject.0.is_empty() && !agent_subject(&csr.info.subject) {
            return Err(Error::CertificateRequest);
        }
        if csr.info.attributes.len() > 1 {
            return Err(Error::CertificateRequest);
        }
        for attr in csr.info.attributes.iter() {
            if attr.oid != EXTENSION_REQ || attr.values.len() != 1 {
                return Err(Error::CertificateRequest);
            }
            let extensions: Vec<Extension> = attr
                .values
                .iter()
                .next()
                .ok_or(Error::CertificateRequest)?
                .decode_as()
                .map_err(malformed)?;
            let mut seen = std::collections::BTreeSet::new();
            for ext in extensions {
                if !seen.insert(ext.extn_id) {
                    return Err(Error::CertificateRequest);
                }
                match ext.extn_id.to_string().as_str() {
                    "2.5.29.19" => {
                        let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                            .map_err(malformed)?;
                        if bc.ca || bc.path_len_constraint.is_some() {
                            return Err(Error::CertificateRequest);
                        }
                    }
                    "2.5.29.15" => {
                        if KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(malformed)?
                            != KeyUsage(KeyUsages::DigitalSignature.into())
                        {
                            return Err(Error::CertificateRequest);
                        }
                    }
                    "2.5.29.37" => {
                        if ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                            .map_err(malformed)?
                            .0
                            != vec![CLIENT_AUTH]
                        {
                            return Err(Error::CertificateRequest);
                        }
                    }
                    _ => return Err(Error::CertificateRequest),
                }
            }
        }
        Ok(Self {
            der: bytes.to_vec(),
            digest: Sha256::digest(bytes).into(),
            spki: Sha256::digest(csr.info.public_key.to_der().map_err(malformed)?).into(),
        })
    }
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn spki(&self) -> [u8; 32] {
        self.spki
    }
    pub fn pem(&self) -> Result<String, Error> {
        use x509_cert::der::{EncodePem, pem::LineEnding};
        CertReq::from_der(&self.der)
            .map_err(malformed)?
            .to_pem(LineEnding::LF)
            .map_err(malformed)
    }
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
    pub trust: rss_mdm_device_trust::DeviceTrust,
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
    pub fn from_trust(
        trust: rss_mdm_device_trust::DeviceTrust,
        max_days: u16,
    ) -> Result<Self, Error> {
        let active = trust.active()?;
        if active.provisioner != "rss-agent"
            || active.kid.is_empty()
            || active.kid.len() > 128
            || !(1..=3650).contains(&max_days)
        {
            return Err(Error::Malformed);
        }
        let der = rss_mdm_device_trust::decode(&active.certificate, 32768)?;
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
            .and_then(|g| rss_mdm_device_trust::decode(&g.certificate, 32768))
            .map(|der| Sha256::digest(der).into())
            .unwrap_or([0; 32])
    }
    fn active_certificate(&self) -> Result<Certificate, Error> {
        Certificate::from_der(&rss_mdm_device_trust::decode(
            &self.trust.active()?.certificate,
            32768,
        )?)
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
        let issuer_bytes = rss_mdm_device_trust::decode(&generation.certificate, 32768)?;
        let issuer = Certificate::from_der(&issuer_bytes).map_err(malformed)?;
        let c = Certificate::from_der(der).map_err(malformed)?;
        let t = &c.tbs_certificate;
        let start = t.validity.not_before.to_unix_duration().as_secs() as i64;
        let end = t.validity.not_after.to_unix_duration().as_secs() as i64;
        if start <= 0
            || end <= start
            || end - start > self.max_seconds
            || end
                > issuer
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs() as i64
            || t.issuer != issuer.tbs_certificate.subject
            || !agent_subject(&t.subject)
            || !rsa(&t.subject_public_key_info.algorithm, RSA)
            || t.get::<BasicConstraints>()
                .map_err(malformed)?
                .is_none_or(|(_, bc)| bc.ca || bc.path_len_constraint.is_some())
            || t.get::<KeyUsage>()
                .map_err(malformed)?
                .is_none_or(|(_, ku)| ku != KeyUsage(KeyUsages::DigitalSignature.into()))
            || t.get::<ExtendedKeyUsage>()
                .map_err(malformed)?
                .is_none_or(|(_, eku)| eku.0 != vec![CLIENT_AUTH])
        {
            return Err(Error::Unauthorized);
        }
        let identity = rss_mdm_device_trust::agent_identity(&c, &generation)?;
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
#[cfg(test)]
#[path = "../tests/agent.rs"]
mod tests;
