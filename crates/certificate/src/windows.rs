//! Windows CSR and device trust validation. No certificate signing key is held here.
//! ref: RustCrypto formats x509-cert/v0.2.5 src/request.rs; rustls client_verifier.rs.
use crate::Error;
use ring::signature;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_cert::{
    TbsCertificate,
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
pub fn rsa_algorithm(algorithm: &AlgorithmIdentifierOwned, oid: ObjectIdentifier) -> bool {
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
    pub fn public_key(&self) -> &x509_cert::spki::SubjectPublicKeyInfoOwned {
        &self.info.public_key
    }
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
#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Lifetime {
    #[default]
    Production,
    Development {
        seconds: u32,
    },
}
impl Lifetime {
    pub fn seconds(self) -> Result<i64, Error> {
        match self {
            Self::Production => Ok(90 * 86400),
            Self::Development { seconds } if (60..=7 * 86400).contains(&seconds) => {
                Ok(i64::from(seconds))
            }
            _ => Err(Error::Malformed),
        }
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
pub fn valid_at(tbs: &TbsCertificate, now: i64) -> bool {
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

#[cfg(test)]
#[path = "../tests/windows.rs"]
mod tests;
