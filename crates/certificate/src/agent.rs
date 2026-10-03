//! Agent-only PKI. Certificate bytes are candidates, never proof of a TLS peer.
//! ref: RustCrypto/formats x509-cert/src/request.rs@x509-cert/v0.2.5;
//! smallstep/certificates authority/provisioner/jwk.go@v0.30.2.
use crate::{Error, HandshakePeer};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature;
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
        asn1::{Any, ObjectIdentifier, OctetString},
    },
    ext::{
        Extension,
        pkix::{
            BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
            name::GeneralName,
        },
    },
    request::CertReq,
    spki::AlgorithmIdentifierOwned,
};
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const STEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37476.9000.64.1");
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
        let expected = format!("CN={SUBJECT}").parse().map_err(malformed)?;
        if !csr.info.subject.0.is_empty() && csr.info.subject != expected {
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
struct Provisioner {
    kind: u8,
    name: OctetString,
    credential: OctetString,
}
pub struct AgentTrust {
    issuer: Certificate,
    issuer_digest: [u8; 32],
    verifier: Arc<dyn ClientCertVerifier>,
    provisioner: String,
    kid: String,
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
    pub fn from_pem(
        bytes: &[u8],
        provisioner: &str,
        kid: &str,
        max_days: u16,
        now: i64,
    ) -> Result<Self, Error> {
        if bytes.len() > 32768
            || provisioner != "rss-agent"
            || kid.is_empty()
            || kid.len() > 128
            || !(1..=3650).contains(&max_days)
        {
            return Err(Error::Malformed);
        }
        let issuer = Certificate::from_pem(bytes).map_err(malformed)?;
        let tbs = &issuer.tbs_certificate;
        if !valid(&issuer, now)
            || tbs
                .get::<BasicConstraints>()
                .map_err(malformed)?
                .is_none_or(|(_, bc)| !bc.ca)
            || tbs
                .get::<KeyUsage>()
                .map_err(malformed)?
                .is_none_or(|(_, ku)| !ku.key_cert_sign())
        {
            return Err(Error::Malformed);
        }
        let der = issuer.to_der().map_err(malformed)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(malformed)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(malformed)?;
        Ok(Self {
            issuer,
            issuer_digest: Sha256::digest(der).into(),
            verifier,
            provisioner: provisioner.into(),
            kid: kid.into(),
            max_seconds: i64::from(max_days) * 86400,
        })
    }
    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.verifier.clone()
    }
    pub fn issuer_digest(&self) -> [u8; 32] {
        self.issuer_digest
    }
    pub fn expires(&self) -> i64 {
        self.issuer
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64
    }
    pub fn permits_window(&self, start: i64, end: i64) -> bool {
        start > 0
            && valid(&self.issuer, start)
            && end > start
            && end <= self.expires()
            && end - start <= self.max_seconds
    }
    fn check(&self, chain: &[CertificateDer<'_>], now: i64) -> Result<Metadata, Error> {
        if chain.is_empty()
            || chain.len() > 4
            || chain.iter().any(|c| c.len() > 32768)
            || !valid(&self.issuer, now)
        {
            return Err(Error::Unauthorized);
        }
        // The configured anchor is the direct signer; auxiliary chain members
        // cannot delegate this Agent purpose to a same-name subordinate CA.
        self.verifier
            .verify_client_cert(
                &chain[0],
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(now as u64)),
            )
            .map_err(|_| Error::Unauthorized)?;
        let c = Certificate::from_der(&chain[0]).map_err(malformed)?;
        let t = &c.tbs_certificate;
        let start = t.validity.not_before.to_unix_duration().as_secs() as i64;
        let end = t.validity.not_after.to_unix_duration().as_secs() as i64;
        let subject = format!("CN={SUBJECT}").parse().map_err(malformed)?;
        if !valid(&c, now)
            || !self.permits_window(start, end)
            || t.issuer != self.issuer.tbs_certificate.subject
            || t.subject != subject
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
        let (_, san) = t
            .get::<SubjectAltName>()
            .map_err(malformed)?
            .ok_or(Error::Unauthorized)?;
        let identity = match san.0.as_slice() {
            [GeneralName::UniformResourceIdentifier(uri)] => uri.to_string(),
            _ => return Err(Error::Unauthorized),
        };
        let remainder = identity
            .strip_prefix("urn:rss-mdm:agent:v1:")
            .ok_or(Error::Unauthorized)?;
        let (tenant, encoded) = remainder.split_once(':').ok_or(Error::Unauthorized)?;
        let tenant = Uuid::parse_str(tenant).map_err(malformed)?;
        let device = URL_SAFE_NO_PAD.decode(encoded).map_err(malformed)?;
        if self::identity(tenant, std::str::from_utf8(&device).map_err(malformed)?)? != identity {
            return Err(Error::Unauthorized);
        }
        let extensions = t.extensions.as_ref().ok_or(Error::Unauthorized)?;
        let mut seen = std::collections::BTreeSet::new();
        if extensions.iter().any(|ext| !seen.insert(ext.extn_id)) {
            return Err(Error::Unauthorized);
        }
        let marker = extensions
            .iter()
            .find(|ext| ext.extn_id == STEP)
            .ok_or(Error::Unauthorized)?;
        let provisioner = Any::from_der(marker.extn_value.as_bytes())
            .map_err(malformed)?
            .sequence(|reader| {
                Ok(Provisioner {
                    kind: u8::decode(reader)?,
                    name: OctetString::decode(reader)?,
                    credential: OctetString::decode(reader)?,
                })
            })
            .map_err(malformed)?;
        if provisioner.kind != 1
            || provisioner.name.as_bytes() != self.provisioner.as_bytes()
            || provisioner.credential.as_bytes() != self.kid.as_bytes()
        {
            return Err(Error::Unauthorized);
        }
        Ok(Metadata {
            profile: PROFILE,
            identity,
            issuer: self.issuer_digest,
            fingerprint: Sha256::digest(&chain[0]).into(),
            spki: Sha256::digest(t.subject_public_key_info.to_der().map_err(malformed)?).into(),
            serial: t.serial_number.as_bytes().to_vec(),
            not_before: start,
            not_after: end,
            provisioner: self.provisioner.clone(),
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
        let refs = chain
            .iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect::<Vec<_>>();
        let metadata = self.check(&refs, now)?;
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
