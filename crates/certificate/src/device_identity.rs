//! Purpose-bound endpoint PKI. Certificate bytes are candidates, never proof of a TLS peer.
//! ref: RustCrypto/formats x509-cert/src/request.rs@x509-cert/v0.2.5;
//! smallstep/certificates authority/provisioner/jwk.go@v0.30.2.
use crate::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature;
use rss_mdm_agent_wire::pki::Purpose;
use sha2::{Digest, Sha256};
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
pub fn subject(purpose: Purpose) -> Result<&'static str, Error> {
    match purpose {
        Purpose::Agent => Ok("rss-mdm-agent"),
        Purpose::DaDevice => Ok("rss-da-device"),
        _ => Err(Error::Unauthorized),
    }
}
pub fn profile(purpose: Purpose) -> Result<&'static str, Error> {
    match purpose {
        Purpose::Agent => Ok("rss-mdm.agent.v1"),
        Purpose::DaDevice => Ok("rss.da.device.v1"),
        _ => Err(Error::Unauthorized),
    }
}
pub fn identity_prefix(purpose: Purpose) -> Result<&'static str, Error> {
    match purpose {
        Purpose::Agent => Ok("urn:rss-mdm:agent:v1:"),
        Purpose::DaDevice => Ok("urn:rss:da:device:v1:"),
        _ => Err(Error::Unauthorized),
    }
}
pub fn provisioner(purpose: Purpose) -> Result<&'static str, Error> {
    match purpose {
        Purpose::Agent => Ok("rss-agent"),
        Purpose::DaDevice => Ok("rss-da-device"),
        _ => Err(Error::Unauthorized),
    }
}
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
fn device_subject(name: &x509_cert::name::Name, expected: &str) -> bool {
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
            && attribute.value.value() == expected.as_bytes()
    })
}
/// Identity comes from the registration owner's authorized database row.
pub fn identity(
    purpose: Purpose,
    service: Uuid,
    tenant: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<String, Error> {
    if tenant.is_nil() {
        return Err(Error::Unauthorized);
    }
    if purpose == Purpose::DaDevice {
        if service.is_nil() {
            return Err(Error::Unauthorized);
        }
        return Ok(format!(
            "{}{service}:{tenant}:{}",
            identity_prefix(purpose)?,
            URL_SAFE_NO_PAD.encode(device.to_string())
        ));
    }
    Ok(format!(
        "{}{tenant}:{}",
        identity_prefix(purpose)?,
        URL_SAFE_NO_PAD.encode(device.to_string())
    ))
}
pub struct VerifiedDeviceCsr {
    purpose: Purpose,
    der: Vec<u8>,
    spki: [u8; 32],
    digest: [u8; 32],
}
impl VerifiedDeviceCsr {
    pub fn verify(bytes: &[u8], purpose: Purpose) -> Result<Self, Error> {
        Self::parse(bytes, purpose).map_err(|_| Error::CertificateRequest)
    }
    fn parse(bytes: &[u8], purpose: Purpose) -> Result<Self, Error> {
        let expected = subject(purpose)?;
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
        if !csr.info.subject.0.is_empty() && !device_subject(&csr.info.subject, expected) {
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
            purpose,
            der: bytes.to_vec(),
            digest: Sha256::digest(bytes).into(),
            spki: Sha256::digest(csr.info.public_key.to_der().map_err(malformed)?).into(),
        })
    }
    pub fn purpose(&self) -> Purpose {
        self.purpose
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
    /// Compare key material, independent of optional RSA AlgorithmIdentifier parameters.
    pub fn uses_key(
        &self,
        key: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    ) -> Result<bool, Error> {
        let own = CertReq::from_der(&self.der)
            .map_err(malformed)?
            .info
            .public_key;
        Ok(own.algorithm.oid == key.algorithm.oid
            && own.subject_public_key == key.subject_public_key)
    }
    pub fn pem(&self) -> Result<String, Error> {
        use x509_cert::der::{EncodePem, pem::LineEnding};
        CertReq::from_der(&self.der)
            .map_err(malformed)?
            .to_pem(LineEnding::LF)
            .map_err(malformed)
    }
}
/// Check the bounded Agent leaf profile after the caller verifies its trust chain.
pub fn validate_leaf_profile(
    c: &Certificate,
    issuer: &Certificate,
    max_seconds: i64,
    purpose: Purpose,
) -> Result<(), Error> {
    let t = &c.tbs_certificate;
    let start = t.validity.not_before.to_unix_duration().as_secs() as i64;
    let end = t.validity.not_after.to_unix_duration().as_secs() as i64;
    if start <= 0
        || end <= start
        || end - start > max_seconds
        || end
            > issuer
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs() as i64
        || t.issuer != issuer.tbs_certificate.subject
        || !device_subject(&t.subject, subject(purpose)?)
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
    Ok(())
}
#[cfg(test)]
#[path = "../tests/agent.rs"]
mod tests;
