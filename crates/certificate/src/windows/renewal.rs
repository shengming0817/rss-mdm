//! WSTEP renewal proof uses RustCrypto CMS parsing and ring signature verification.
//! ref: RustCrypto/formats cms-0.2.3 src/signed_data.rs; Microsoft certificate-renewal-windows-mdm.
use super::*;
use cms::{
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use x509_cert::der::asn1::OctetString;
const SIGNED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// CSR bytes obtained only after the existing enrollment identity signs a valid renewal.
pub struct RenewalProof {
    csr: Vec<u8>,
    fingerprint: [u8; 32],
    expires: i64,
}
impl RenewalProof {
    pub fn csr(&self) -> &[u8] {
        &self.csr
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub fn expires(&self) -> i64 {
        self.expires
    }
}
impl WindowsEnrollmentAuthority {
    /// Verify the current TLS leaf, CMS signer, signed content and new key proof of possession.
    /// The registration owner must still fence current credentials and retirement transactionally.
    pub fn renewal(
        &self,
        cms: &[u8],
        current_leaf: &[u8],
        now: i64,
    ) -> Result<RenewalProof, Error> {
        if cms.len() > 256 * 1024 {
            return Err(Error::CertificateRequest);
        }
        let checked = self.verify(&[CertificateDer::from(current_leaf)], now)?;
        let certificate = Certificate::from_der(current_leaf).map_err(invalid)?;
        let expiry = certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        if expiry.saturating_sub(now as u64) > 7 * 86400 {
            return Err(Error::Unauthorized);
        }
        let content = ContentInfo::from_der(cms).map_err(invalid)?;
        if content.content_type != SIGNED || content.to_der().map_err(invalid)? != cms {
            return Err(Error::CertificateRequest);
        }
        let signed: SignedData = content.content.decode_as().map_err(invalid)?;
        if signed.signer_infos.0.len() != 1
            || signed.digest_algorithms.len() != 1
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
        if sid.issuer != certificate.tbs_certificate.issuer
            || sid.serial_number != certificate.tbs_certificate.serial_number
            || !rsa_algorithm(&signer.digest_alg, SHA256)
            || !signed
                .digest_algorithms
                .iter()
                .all(|a| rsa_algorithm(a, SHA256))
            || !(rsa_algorithm(&signer.signature_algorithm, RSA)
                || rsa_algorithm(&signer.signature_algorithm, SHA256_RSA))
        {
            return Err(Error::CertificateRequest);
        }
        let payload: OctetString = signed
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or(Error::CertificateRequest)?
            .decode_as()
            .map_err(invalid)?;
        let csr = payload.as_bytes();
        if csr.len() > 32768 {
            return Err(Error::CertificateRequest);
        }
        let input = if let Some(attrs) = &signer.signed_attrs {
            if attrs.len() > 32 {
                return Err(Error::CertificateRequest);
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
                        content_type =
                            value.decode_as::<ObjectIdentifier>().map_err(invalid)? == DATA;
                    } else {
                        digest = value
                            .decode_as::<OctetString>()
                            .map_err(invalid)?
                            .as_bytes()
                            == Sha256::digest(csr).as_slice();
                    }
                }
            }
            if !content_type || !digest {
                return Err(Error::CertificateRequest);
            }
            attrs.to_der().map_err(invalid)?
        } else {
            csr.to_vec()
        };
        signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or(Error::CertificateRequest)?,
        )
        .verify(&input, signer.signature.as_bytes())
        .map_err(|_| Error::CertificateRequest)?;
        let request = Csr::verify(csr)?;
        if request.info.public_key == certificate.tbs_certificate.subject_public_key_info {
            return Err(Error::CertificateRequest);
        }
        Ok(RenewalProof {
            csr: csr.to_vec(),
            fingerprint: checked.fingerprint(),
            expires: expiry as i64,
        })
    }
}
