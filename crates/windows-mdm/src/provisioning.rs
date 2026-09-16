//! Bounded provisioning encoder. Values are supplied by the product's verified enrollment.
//! ref: Microsoft MS-MDE2 §3.4.4.1.1.2.2 RequestSecurityTokenResponseCollection.
use crate::{CodecLimits, Result, Secret, bound, text, xml::Output};
use base64::{Engine, engine::general_purpose::STANDARD};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Enrollment profile selecting the certificate store in the generated document.
pub enum EnrollmentType {
    /// Use the user personal certificate store and explicit subject selection criteria.
    Full,
    /// Use the system personal store; device key association requires product validation.
    Device,
}
impl EnrollmentType {
    /// Return the exact enrollment profile token (`Full` or `Device`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Device => "Device",
        }
    }
}
/// Caller-verified enrollment material for the fixed provisioning template.
/// Certificate authenticity, key binding, endpoint authorization and credential generation
/// belong to the product. Encoding checks bounds and syntax, not these trust assertions.
pub struct Provisioning<'a> {
    /// Profile controlling certificate store selection.
    pub enrollment_type: EnrollmentType,
    /// Product-assigned enterprise device identity, emitted as EntDMID.
    pub enterprise_device_id: &'a str,
    /// Caller-verified issuer certificate bytes, base64-encoded into Root/System.
    pub issuer: &'a [u8],
    /// Caller-verified issued certificate bytes for the selected personal store.
    pub certificate: &'a [u8],
    /// Exactly 40 hexadecimal characters naming the issuer store entry.
    pub issuer_thumbprint: &'a str,
    /// Exactly 40 hexadecimal characters naming the issued certificate store entry.
    pub certificate_thumbprint: &'a str,
    /// Certificate subject used for Full enrollment selection; encoder does not parse the certificate.
    pub certificate_subject: &'a str,
    /// Nonblank management address; encoder does not enforce URL scheme or authorize it.
    pub management_url: &'a str,
    /// Nonblank DMClient provider identity and server authentication name.
    pub provider_id: &'a str,
    /// Nonblank client authentication name.
    pub username: &'a str,
    /// Nonblank client BASIC secret, included in cleartext XML.
    pub client_password: Secret<&'a str>,
    /// Nonblank server DIGEST secret, included in cleartext XML.
    pub server_password: Secret<&'a str>,
    /// Exactly 32 caller-generated nonce bytes, emitted in base64.
    pub server_nonce: &'a [u8],
}
fn characteristic(w: &mut Output<'_>, name: &str) -> Result<()> {
    w.start("characteristic", &[("type", name)])
}
fn end(w: &mut Output<'_>) -> Result<()> {
    w.end("characteristic")
}
fn parm(w: &mut Output<'_>, name: &str, value: &str) -> Result<()> {
    w.start("parm", &[("name", name), ("value", value)])?;
    w.end("parm")
}
/// Render provisioning XML in memory without enrollment, certificate installation or I/O.
/// Checks binary/text budgets, nonblank legal XML strings, 40-hex-digit thumbprints
/// and a 32-byte server nonce. Violations return `InvalidValue` or `LimitExceeded`.
/// Output is bounded by [`CodecLimits::binary_bytes`] and XML structure budgets.
/// Contains certificates and plaintext credential values; callers must protect the bytes.
pub fn encode(p: &Provisioning<'_>, l: &CodecLimits) -> Result<Vec<u8>> {
    for cert in [p.issuer, p.certificate] {
        bound(cert.len(), l.binary_bytes)?;
    }
    for value in [
        p.provider_id,
        p.enterprise_device_id,
        p.username,
        p.certificate_subject,
        p.management_url,
        p.client_password.0,
        p.server_password.0,
    ] {
        text(value, l.uri_bytes, false)?;
    }
    for fingerprint in [p.issuer_thumbprint, p.certificate_thumbprint] {
        if fingerprint.len() != 40 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(crate::CodecError::InvalidValue);
        }
    }
    if p.server_nonce.len() != 32 {
        return Err(crate::CodecError::InvalidValue);
    }
    let mut w = Output::new(l.binary_bytes, l);
    w.start("wap-provisioningdoc", &[("version", "1.1")])?;
    characteristic(&mut w, "CertificateStore")?;
    for (store, location, fingerprint, certificate) in [
        ("Root", "System", p.issuer_thumbprint, p.issuer),
        (
            "My",
            match p.enrollment_type {
                EnrollmentType::Full => "User",
                EnrollmentType::Device => "System",
            },
            p.certificate_thumbprint,
            p.certificate,
        ),
    ] {
        characteristic(&mut w, store)?;
        characteristic(&mut w, location)?;
        characteristic(&mut w, fingerprint)?;
        parm(&mut w, "EncodedCertificate", &STANDARD.encode(certificate))?;
        end(&mut w)?;
        if store == "My" {
            characteristic(&mut w, "PrivateKeyContainer")?;
            end(&mut w)?;
        }
        end(&mut w)?;
        end(&mut w)?;
    }
    end(&mut w)?;
    characteristic(&mut w, "APPLICATION")?;
    for (name, value) in [
        ("APPID", "w7"),
        ("PROVIDER-ID", p.provider_id),
        ("NAME", p.provider_id),
        ("ADDR", p.management_url),
        ("ROLE", "32"),
        ("PROTOVER", "1.2"),
        ("DEFAULTENCODING", "application/vnd.syncml.dm+xml"),
    ] {
        parm(&mut w, name, value)?;
    }
    // Full enrollment has an explicit user-store selection. The documented Device
    // sample contradicts the CSP's Stores value; let its enrollment key association
    // select the system certificate and verify that path separately in Windows T3.
    if p.enrollment_type == EnrollmentType::Full {
        let subject: String = p
            .certificate_subject
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        parm(
            &mut w,
            "SSLCLIENTCERTSEARCHCRITERIA",
            &format!("Subject={subject}&Stores=My%5CUser"),
        )?;
    }
    characteristic(&mut w, "APPAUTH")?;
    for (name, value) in [
        ("AAUTHLEVEL", "APPSRV"),
        ("AAUTHTYPE", "BASIC"),
        ("AAUTHNAME", p.username),
        ("AAUTHSECRET", p.client_password.0),
    ] {
        parm(&mut w, name, value)?;
    }
    end(&mut w)?;
    characteristic(&mut w, "APPAUTH")?;
    for (name, value) in [
        ("AAUTHLEVEL", "CLIENT"),
        ("AAUTHTYPE", "DIGEST"),
        ("AAUTHNAME", p.provider_id),
        ("AAUTHSECRET", p.server_password.0),
    ] {
        parm(&mut w, name, value)?;
    }
    parm(&mut w, "AAUTHDATA", &STANDARD.encode(p.server_nonce))?;
    end(&mut w)?;
    end(&mut w)?;
    characteristic(&mut w, "DMClient")?;
    characteristic(&mut w, "Provider")?;
    characteristic(&mut w, p.provider_id)?;
    parm(&mut w, "EntDMID", p.enterprise_device_id)?;
    end(&mut w)?;
    end(&mut w)?;
    end(&mut w)?;
    w.end("wap-provisioningdoc")?;
    w.finish()
}
