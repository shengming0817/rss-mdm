use super::*;
const PASSWORD: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified WS-Security PasswordText material; parsing does not authenticate it.
pub struct UsernameToken {
    /// Nonblank token ID bounded by `identifier_bytes`.
    pub id: String,
    /// Nonblank username claim bounded by `field_bytes`.
    pub username: Secret<String>,
    /// Plaintext password (empty only for certificate-authenticated renewal), bounded by `field_bytes`; encoded XML exposes its value.
    pub password: Secret<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
/// WS-Security timestamp strings checked for RFC 3339 syntax only.
/// The codec does not check ordering, expiry, current time or replay; the verifier must.
pub struct Timestamp {
    /// Nonblank timestamp ID bounded by `identifier_bytes`.
    pub id: String,
    /// RFC 3339 creation text bounded by `identifier_bytes`; no clock comparison.
    pub created: String,
    /// RFC 3339 expiry text bounded by `identifier_bytes`; no expiry/order enforcement.
    pub expires: String,
}
/// Unverified exported certificate token; neither token possession nor parsing authenticates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateToken {
    /// WS-Security token identity.
    pub id: String,
    /// Exported certificate bytes; the channel must verify a signature with the current parent.
    pub certificate: Secret<Vec<u8>>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
/// Supported unverified WS-Security fields; token and timestamp identities must differ.
/// Signature, password and freshness verification belong to the certificate/channel owners.
pub struct Security {
    /// Optional timestamp; required on IssueResponse by the SOAP profile.
    pub timestamp: Option<Timestamp>,
    /// Optional PasswordText token for primary enrollment.
    pub username: Option<UsernameToken>,
    /// Unverified certificate token; XCEP policy alone has no authentication side effects.
    pub certificate: Option<CertificateToken>,
    /// Presence only; signature verification must use the original XML bytes.
    pub signature: bool,
}
fn id(p: &mut Input<'_>, ns: &str, name: &str) -> Result<String> {
    let s = p.start(ns, name)?;
    s.attrs(&[(UTILITY, "Id")])?;
    let id = s.attr(UTILITY, "Id").ok_or(E::Structure)?;
    text(id, p.limits.identifier_bytes, false)?;
    Ok(id.into())
}
pub(super) fn read(p: &mut Input<'_>) -> Result<Security> {
    understood(&p.start(SECURITY, "Security")?)?;
    let mut timestamp = None;
    let mut username = None;
    let mut certificate = None;
    let mut signature = false;
    loop {
        if p.is(UTILITY, "Timestamp")? {
            if timestamp.is_some() {
                return Err(E::Duplicate);
            }
            let id = id(p, UTILITY, "Timestamp")?;
            let created = p.scalar(UTILITY, "Created", p.limits.identifier_bytes, false)?;
            let expires = p.scalar(UTILITY, "Expires", p.limits.identifier_bytes, false)?;
            p.end(UTILITY, "Timestamp")?;
            timestamp = Some(Timestamp {
                id,
                created,
                expires,
            });
        } else if p.is(SECURITY, "UsernameToken")? {
            if username.is_some() {
                return Err(E::Duplicate);
            }
            let id = id(p, SECURITY, "UsernameToken")?;
            let user = p.scalar(SECURITY, "Username", p.limits.field_bytes, false)?;
            let s = p.start(SECURITY, "Password")?;
            s.attrs(&[("", "Type")])?;
            if s.attr("", "Type") != Some(PASSWORD) {
                return Err(E::Unsupported);
            }
            let password = p.content(SECURITY, "Password", p.limits.field_bytes, true)?;
            p.end(SECURITY, "UsernameToken")?;
            username = Some(UsernameToken {
                id,
                username: Secret(user),
                password: Secret(password),
            });
        } else if p.is(SECURITY, "BinarySecurityToken")? {
            if certificate.is_some() {
                return Err(E::Duplicate);
            }
            let token = p.start(SECURITY, "BinarySecurityToken")?;
            token.attrs(&[(UTILITY, "Id"), ("", "ValueType"), ("", "EncodingType")])?;
            if token.attr("", "ValueType")
                != Some(
                    "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentUserToken",
                )
                || token.attr("", "EncodingType")
                    != Some(
                        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary",
                    )
            {
                return Err(E::Unsupported);
            }
            let id = token.attr(UTILITY, "Id").ok_or(E::Structure)?.to_owned();
            let value = p.content(
                SECURITY,
                "BinarySecurityToken",
                p.limits.binary_bytes * 2,
                false,
            )?;
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value.split_whitespace().collect::<String>())
                .map_err(|_| E::InvalidValue)?;
            bound(bytes.len(), p.limits.binary_bytes)?;
            certificate = Some(CertificateToken {
                id,
                certificate: Secret(bytes),
            });
        } else if p.is("http://www.w3.org/2000/09/xmldsig#", "Signature")? {
            if signature {
                return Err(E::Duplicate);
            }
            p.skip("http://www.w3.org/2000/09/xmldsig#", "Signature")?;
            signature = true;
        } else {
            break;
        }
    }
    p.end(SECURITY, "Security")?;
    let s = Security {
        timestamp,
        username,
        certificate,
        signature,
    };
    validate(&s, p.limits)?;
    Ok(s)
}
pub(super) fn validate(s: &Security, l: &CodecLimits) -> Result<()> {
    if s.timestamp.is_none() && s.username.is_none() && s.certificate.is_none() {
        return Err(E::Structure);
    }
    if s.username.is_some() && s.certificate.is_some()
        || s.signature && (s.certificate.is_none() || s.timestamp.is_none())
    {
        return Err(E::Structure);
    }
    if let Some(t) = &s.certificate {
        text(&t.id, l.identifier_bytes, false)?;
        bound(t.certificate.0.len(), l.binary_bytes)?;
        if t.certificate.0.is_empty() || s.timestamp.as_ref().is_some_and(|v| v.id == t.id) {
            return Err(E::Structure);
        }
    }
    if let Some(t) = &s.timestamp {
        for v in [&t.id, &t.created, &t.expires] {
            text(v, l.identifier_bytes, false)?;
        }
        for value in [&t.created, &t.expires] {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .map_err(|_| E::InvalidValue)?;
        }
    }
    if let Some(t) = &s.username {
        text(&t.id, l.identifier_bytes, false)?;
        text(&t.username.0, l.field_bytes, false)?;
        text(&t.password.0, l.field_bytes, true)?;
    }
    if let (Some(a), Some(b)) = (&s.timestamp, &s.username)
        && a.id == b.id
    {
        return Err(E::Duplicate);
    }
    Ok(())
}
pub(super) fn write(w: &mut Output<'_>, s: &Security, l: &CodecLimits) -> Result<()> {
    if s.signature {
        return Err(E::Unsupported);
    }
    w.start("o:Security", &[("s:mustUnderstand", "1")])?;
    if let Some(t) = &s.timestamp {
        w.start("u:Timestamp", &[("u:Id", &t.id)])?;
        w.scalar("u:Created", &t.created, l.identifier_bytes, false)?;
        w.scalar("u:Expires", &t.expires, l.identifier_bytes, false)?;
        w.end("u:Timestamp")?;
    }
    if let Some(t) = &s.username {
        w.start("o:UsernameToken", &[("u:Id", &t.id)])?;
        w.scalar("o:Username", &t.username.0, l.field_bytes, false)?;
        w.start("o:Password", &[("Type", PASSWORD)])?;
        w.content(&t.password.0, l.field_bytes)?;
        w.end("o:Password")?;
        w.end("o:UsernameToken")?;
    }
    if let Some(t) = &s.certificate {
        use base64::Engine;
        let value = base64::engine::general_purpose::STANDARD.encode(&t.certificate.0);
        w.start("o:BinarySecurityToken", &[("u:Id", &t.id), ("ValueType", "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentUserToken"), ("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary")])?;
        w.content(&value, l.binary_bytes * 2)?;
        w.end("o:BinarySecurityToken")?;
    }
    w.end("o:Security")
}
