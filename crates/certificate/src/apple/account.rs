//! Apple bootstrap CMS integrity and narrowly scoped Managed Apple Account JWT signing.
//! ref: RustCrypto/formats cms/src/signed_data.rs@cms/v0.2.3;
//! apple/device-management mdm/checkin/gettoken.yaml@09f249a06e7e3289930bf6d05f38fb562f748ebf.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SIGNED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const EC_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// Signature integrity is not Apple device attestation or tenant/account authority.
pub struct EnrollmentRequest {
    pub payload: Vec<u8>,
    pub signer: [u8; 32],
}
pub fn enrollment_request(bytes: &[u8], now: i64) -> Result<EnrollmentRequest, Error> {
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return Err(Error::Malformed);
    }
    let content = ContentInfo::from_der(bytes).map_err(invalid)?;
    if content.content_type != SIGNED || content.to_der().map_err(invalid)? != bytes {
        return Err(Error::CertificateRequest);
    }
    let signed: SignedData = content.content.decode_as().map_err(invalid)?;
    if signed.signer_infos.0.len() != 1
        || signed.digest_algorithms.len() != 1
        || !signed.digest_algorithms.iter().all(|a| a.oid == SHA256)
        || signed.encap_content_info.econtent_type != DATA
    {
        return Err(Error::CertificateRequest);
    }
    let signer = signed
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(Error::CertificateRequest)?;
    let SignerIdentifier::IssuerAndSerialNumber(sid) = &signer.sid else {
        return Err(Error::CertificateRequest);
    };
    let certificates = signed
        .certificates
        .as_ref()
        .ok_or(Error::CertificateRequest)?;
    if certificates.0.len() > 8 {
        return Err(Error::CertificateRequest);
    }
    let matches: Vec<_> = certificates
        .0
        .iter()
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c)
                if c.tbs_certificate.issuer == sid.issuer
                    && c.tbs_certificate.serial_number == sid.serial_number =>
            {
                Some(c)
            }
            _ => None,
        })
        .collect();
    if matches.len() != 1 || signer.digest_alg.oid != SHA256 {
        return Err(Error::CertificateRequest);
    }
    let certificate = matches[0];
    if !valid(certificate, now) {
        return Err(Error::Expired);
    }
    let payload: OctetString = signed
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(Error::CertificateRequest)?
        .decode_as()
        .map_err(invalid)?;
    let payload = payload.as_bytes();
    if payload.is_empty() || payload.len() > 32768 {
        return Err(Error::Malformed);
    }
    let input = if let Some(attrs) = &signer.signed_attrs {
        if attrs.len() > 32 {
            return Err(Error::Malformed);
        }
        let mut content_type = false;
        let mut digest = false;
        let mut seen = std::collections::BTreeSet::new();
        for attr in attrs.iter() {
            if !seen.insert(attr.oid) {
                return Err(Error::CertificateRequest);
            }
            if attr.oid == CONTENT_TYPE || attr.oid == MESSAGE_DIGEST {
                if attr.values.len() != 1 {
                    return Err(Error::CertificateRequest);
                }
                let value = attr.values.iter().next().ok_or(Error::CertificateRequest)?;
                if attr.oid == CONTENT_TYPE {
                    content_type = value.decode_as::<ObjectIdentifier>().map_err(invalid)? == DATA;
                } else {
                    digest = value
                        .decode_as::<OctetString>()
                        .map_err(invalid)?
                        .as_bytes()
                        == Sha256::digest(payload).as_slice();
                }
            }
        }
        if !content_type || !digest {
            return Err(Error::CertificateRequest);
        }
        attrs.to_der().map_err(invalid)?
    } else {
        payload.to_vec()
    };
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let algorithm: &dyn signature::VerificationAlgorithm = if spki.algorithm.oid == RSA
        && (signer.signature_algorithm.oid == RSA || signer.signature_algorithm.oid == SHA256_RSA)
    {
        &signature::RSA_PKCS1_2048_8192_SHA256
    } else if spki.algorithm.oid == EC
        && signer.signature_algorithm.oid == EC_SHA256
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|v| v.decode_as::<ObjectIdentifier>().ok())
            == Some(P256)
    {
        &signature::ECDSA_P256_SHA256_ASN1
    } else {
        return Err(Error::CertificateRequest);
    };
    signature::UnparsedPublicKey::new(
        algorithm,
        spki.subject_public_key
            .as_bytes()
            .ok_or(Error::CertificateRequest)?,
    )
    .verify(&input, signer.signature.as_bytes())
    .map_err(|_| Error::CertificateRequest)?;
    Ok(EnrollmentRequest {
        payload: payload.to_vec(),
        signer: Sha256::digest(certificate.to_der().map_err(invalid)?).into(),
    })
}
/// The private key corresponds to the public certificate registered with Apple for this server.
pub struct ManagedAccountTokenSigner {
    signer: ProfileSigner,
}
impl ManagedAccountTokenSigner {
    pub fn from_bytes(certificate: &[u8], key: &[u8], now: i64) -> Result<Self, Error> {
        Ok(Self {
            signer: ProfileSigner::from_bytes(certificate, key, now)?,
        })
    }
    pub fn expires(&self) -> u64 {
        self.signer.expires()
    }
    pub fn sign(&self, server: Uuid, now: i64) -> Result<String, Error> {
        if server.is_nil() || !valid(&self.signer.certificates[0], now) {
            return Err(Error::Expired);
        }
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims=serde_json::to_vec(&serde_json::json!({"iss":server.to_string(),"iat":now,"jti":Uuid::new_v4().to_string(),"service_type":"com.apple.maid"})).map_err(invalid)?;
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims));
        let mut signature = vec![0; self.signer.key.public().modulus_len()];
        self.signer
            .key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .map_err(invalid)?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}
