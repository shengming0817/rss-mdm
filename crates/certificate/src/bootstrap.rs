//! Short-lived bootstrap identity: never an MDM or Agent runtime certificate.
//! ref: RFC 5280 section 4.1.2.6; RustCrypto x509-cert 0.2.5 request.rs.
use crate::Error;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_cert::{der::Encode, name::Name};
pub const PURPOSE: &str = "rss-mdm-agent-bootstrap";
pub fn subject(installation: Uuid, attempt: Uuid) -> String {
    format!(
        "OU={PURPOSE},CN={}",
        crate::apple::subject(installation, attempt)
    )
}
pub fn parse_subject(name: &Name) -> Result<(Uuid, Uuid), Error> {
    if name.0.len() != 2 {
        return Err(Error::Unauthorized);
    }
    let mut cn = name.clone();
    cn.0.retain(|rdn| rdn.0.iter().any(|v| v.oid.to_string() == "2.5.4.3"));
    let ou = name
        .0
        .iter()
        .find(|rdn| rdn.0.iter().any(|v| v.oid.to_string() == "2.5.4.11"))
        .ok_or(Error::Unauthorized)?;
    if ou.0.len() != 1
        || ou
            .0
            .iter()
            .next()
            .is_none_or(|v| v.value.value() != PURPOSE.as_bytes())
    {
        return Err(Error::Unauthorized);
    }
    crate::apple::parse_subject(&cn)
}
pub struct Csr {
    installation: Uuid,
    attempt: Uuid,
    spki: [u8; 32],
    digest: [u8; 32],
}
impl Csr {
    pub fn verify(bytes: &[u8]) -> Result<Self, Error> {
        let csr = crate::apple::verified_rsa_csr(bytes)?;
        let (installation, attempt) = parse_subject(&csr.info.subject)?;
        Ok(Self {
            installation,
            attempt,
            spki: Sha256::digest(csr.info.public_key.to_der().map_err(|_| Error::Malformed)?)
                .into(),
            digest: Sha256::digest(bytes).into(),
        })
    }
    pub fn installation(&self) -> Uuid {
        self.installation
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
