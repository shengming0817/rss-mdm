//! ADE S/MIME and Apple-signed MachineInfo; neither grants a product device principal.
//! ref: openssl openssl/src/pkcs7.rs@openssl-v0.10.81;
//! Apple devicemanagement/machineinfo and examining-server-tokens.
use crate::Error;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::PKey,
    rsa::Rsa,
    stack::Stack,
    x509::{X509, X509NameBuilder, store::X509StoreBuilder, verify::X509VerifyParam},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct KeyPair {
    pub certificate: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
}
pub fn generate_key(now: i64) -> Result<KeyPair, Error> {
    let key = PKey::from_rsa(Rsa::generate(2048).map_err(invalid)?).map_err(invalid)?;
    let mut name = X509NameBuilder::new().map_err(invalid)?;
    name.append_entry_by_text("CN", "RSS ADE token encryption")
        .map_err(invalid)?;
    let name = name.build();
    let mut cert = X509::builder().map_err(invalid)?;
    cert.set_version(2).map_err(invalid)?;
    let mut serial = BigNum::new().map_err(invalid)?;
    serial
        .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .map_err(invalid)?;
    cert.set_serial_number(serial.to_asn1_integer().map_err(invalid)?.as_ref())
        .map_err(invalid)?;
    cert.set_subject_name(&name).map_err(invalid)?;
    cert.set_issuer_name(&name).map_err(invalid)?;
    cert.set_pubkey(&key).map_err(invalid)?;
    cert.set_not_before(Asn1Time::from_unix(now).map_err(invalid)?.as_ref())
        .map_err(invalid)?;
    cert.set_not_after(
        Asn1Time::from_unix(now.checked_add(10 * 365 * 86400).ok_or(Error::Malformed)?)
            .map_err(invalid)?
            .as_ref(),
    )
    .map_err(invalid)?;
    cert.sign(&key, MessageDigest::sha256()).map_err(invalid)?;
    Ok(KeyPair {
        certificate: cert.build().to_pem().map_err(invalid)?,
        private_key: Zeroizing::new(key.private_key_to_pkcs8().map_err(invalid)?),
    })
}
/// Accept the actual encrypted S/MIME file, never a caller-supplied plaintext token.
pub fn decrypt_token(
    bytes: &[u8],
    certificate: &[u8],
    private_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return Err(Error::Malformed);
    }
    let (envelope, detached) = Pkcs7::from_smime(bytes).map_err(invalid)?;
    if detached.is_some() {
        return Err(Error::Malformed);
    }
    let plain = Zeroizing::new(
        envelope
            .decrypt(
                PKey::private_key_from_der(private_key)
                    .map_err(invalid)?
                    .as_ref(),
                X509::from_pem(certificate).map_err(invalid)?.as_ref(),
                Pkcs7Flags::BINARY,
            )
            .map_err(invalid)?,
    );
    if plain.len() > 32768 {
        return Err(Error::Malformed);
    }
    let split = plain
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| {
            plain
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|i| (i, i + 2))
        })
        .ok_or(Error::Malformed)?;
    let headers = std::str::from_utf8(&plain[..split.0]).map_err(|_| Error::Malformed)?;
    if !headers.lines().any(|l| {
        l.to_ascii_lowercase()
            .starts_with("content-type: text/plain")
    }) || headers.lines().any(|l| {
        l.to_ascii_lowercase()
            .starts_with("content-transfer-encoding:")
            && !matches!(
                l.split_once(':').map(|(_, v)| v.trim()),
                Some("7bit" | "8bit" | "binary")
            )
    }) {
        return Err(Error::Malformed);
    }
    let payload = split.1;
    // Apple's inner MIME text/plain part contains the JSON OAuth credentials.
    Ok(Zeroizing::new(plain[payload..].to_vec()))
}

/// Private construction forces protocol callers through CMS and manufacturer-chain validation.
pub struct MachineInfo {
    serial: String,
    udid: String,
    product: String,
    os_version: String,
    build: String,
    digest: [u8; 32],
}
impl MachineInfo {
    pub fn serial(&self) -> &str {
        &self.serial
    }
    pub fn udid(&self) -> &str {
        &self.udid
    }
    pub fn product(&self) -> &str {
        &self.product
    }
    pub fn os_version(&self) -> &str {
        &self.os_version
    }
    pub fn build(&self) -> &str {
        &self.build
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
pub struct MachineVerifier {
    roots: Vec<X509>,
}
impl MachineVerifier {
    pub fn apple() -> Result<Self, Error> {
        Self::from_roots(&[
            include_bytes!("../../fixtures/AppleIncRootCertificate.cer"),
            include_bytes!("../../fixtures/AppleRootCA-G3.cer"),
        ])
    }
    #[cfg(feature = "integration")]
    pub fn fixture(root: &[u8]) -> Result<Self, Error> {
        Self::from_roots(&[root])
    }
    fn from_roots(roots: &[&[u8]]) -> Result<Self, Error> {
        if roots.is_empty() || roots.len() > 4 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            roots: roots
                .iter()
                .map(|b| X509::from_der(b).map_err(invalid))
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn verify(&self, bytes: &[u8], now: i64) -> Result<MachineInfo, Error> {
        if bytes.is_empty() || bytes.len() > 128 * 1024 {
            return Err(Error::Malformed);
        }
        let signed = Pkcs7::from_der(bytes).map_err(invalid)?;
        let signers = signed
            .signers(Stack::new().map_err(invalid)?.as_ref(), Pkcs7Flags::empty())
            .map_err(invalid)?;
        if signers.len() != 1 {
            return Err(Error::Unauthorized);
        }
        let mut store = X509StoreBuilder::new().map_err(invalid)?;
        for root in &self.roots {
            store.add_cert(root.clone()).map_err(invalid)?;
        }
        let mut param = X509VerifyParam::new().map_err(invalid)?;
        param.set_time(now);
        // Apple device identity certificates are not email-protection certificates.
        param
            .set_purpose(openssl::x509::X509PurposeId::ANY)
            .map_err(invalid)?;
        param.set_depth(6);
        store.set_param(&param).map_err(invalid)?;
        let mut plain = Vec::new();
        signed
            .verify(
                Stack::new().map_err(invalid)?.as_ref(),
                &store.build(),
                None,
                Some(&mut plain),
                Pkcs7Flags::BINARY,
            )
            .map_err(|_| Error::Unauthorized)?;
        if plain.len() > 32768 {
            return Err(Error::Malformed);
        }
        let value = plist::Value::from_reader(std::io::Cursor::new(&plain))
            .map_err(|_| Error::Malformed)?;
        let data = value.as_dictionary().ok_or(Error::Malformed)?;
        let field = |name: &str| -> Result<String, Error> {
            let s = data
                .get(name)
                .and_then(plist::Value::as_string)
                .ok_or(Error::Malformed)?;
            if s.is_empty() || s.len() > 128 || s.chars().any(char::is_control) {
                return Err(Error::Malformed);
            }
            Ok(s.to_owned())
        };
        let product = field("PRODUCT")?;
        let os_version = field("OS_VERSION")?;
        if !(product.starts_with("Mac") || product.starts_with("iMac"))
            || os_version
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .is_none_or(|v| v < 15)
        {
            return Err(Error::Unauthorized);
        }
        Ok(MachineInfo {
            serial: field("SERIAL")?,
            udid: field("UDID")?,
            product,
            os_version,
            build: field("VERSION")?,
            digest: Sha256::digest(&plain).into(),
        })
    }
}
fn invalid(_: openssl::error::ErrorStack) -> Error {
    Error::CertificateRequest
}
