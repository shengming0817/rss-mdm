//! Local generation only. Apple and public CA signatures remain external authorities.
//! ref: rust-openssl openssl/src/x509/mod.rs and openssl/src/rsa.rs.
use crate::{model::Bundle, *};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509Req,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
use x509_cert::{
    der::Decode,
    ext::pkix::{BasicConstraints as Bc, KeyUsage as Ku},
};
use zeroize::Zeroizing;

fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::Material
}
fn key(algorithm: Algorithm) -> Result<PKey<Private>, Error> {
    match algorithm {
        Algorithm::Rsa2048 => {
            PKey::from_rsa(Rsa::generate(2048).map_err(invalid)?).map_err(invalid)
        }
        Algorithm::Rsa3072 => {
            PKey::from_rsa(Rsa::generate(3072).map_err(invalid)?).map_err(invalid)
        }
        Algorithm::P256 => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(invalid)?;
            PKey::from_ec_key(EcKey::generate(&group).map_err(invalid)?).map_err(invalid)
        }
    }
}
fn san(input: &Generate) -> Result<SubjectAlternativeName, Error> {
    if input.sans.len() > 32 {
        return Err(Error::Malformed);
    }
    let mut san = SubjectAlternativeName::new();
    for name in &input.sans {
        if name.parse::<std::net::IpAddr>().is_ok() {
            san.ip(name);
            continue;
        }
        let plain = name.strip_prefix("*.").unwrap_or(name);
        if plain.is_empty()
            || plain.len() > 253
            || !plain.is_ascii()
            || plain.split('.').any(|p| {
                p.is_empty()
                    || p.len() > 63
                    || p.starts_with('-')
                    || p.ends_with('-')
                    || !p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(Error::Malformed);
        }
        san.dns(name);
    }
    Ok(san)
}
fn file(name: &str, format: Format, data: Vec<u8>) -> ImportFile {
    ImportFile {
        name: name.into(),
        format,
        data: Zeroizing::new(STANDARD.encode(Zeroizing::new(data))),
        password: None,
    }
}
fn issuer(bundle: &Bundle, now: i64) -> Result<(X509, PKey<Private>), Error> {
    for file in &bundle.files {
        let bytes = Zeroizing::new(
            STANDARD
                .decode(file.data.as_bytes())
                .map_err(|_| Error::Integrity)?,
        );
        let cert = if bytes.starts_with(b"-----BEGIN CERTIFICATE") {
            X509::from_pem(&bytes)
        } else {
            X509::from_der(&bytes)
        };
        let Ok(cert) = cert else { continue };
        let tbs = x509_cert::Certificate::from_der(&cert.to_der().map_err(invalid)?)
            .map_err(invalid)?
            .tbs_certificate;
        if tbs.get::<Bc>().map_err(invalid)?.is_none_or(|(_, v)| !v.ca)
            || tbs
                .get::<Ku>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| !v.key_cert_sign())
        {
            continue;
        }
        let facts = crate::materials::facts(&cert)?;
        if facts.not_before > now || facts.not_after <= now {
            return Err(Error::Material);
        }
        let public = cert.public_key().map_err(invalid)?;
        for file in &bundle.files {
            if !file.name.ends_with(".pk8") {
                continue;
            }
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(file.data.as_bytes())
                    .map_err(|_| Error::Integrity)?,
            );
            let Ok(key) = PKey::private_key_from_pkcs8(&bytes) else {
                continue;
            };
            if key.public_eq(&public) {
                return Ok((cert, key));
            }
        }
    }
    Err(Error::KeyMismatch)
}
pub(crate) fn generate(
    input: &Generate,
    issuer_material: Option<&Bundle>,
    now: i64,
) -> Result<(Bundle, Vec<MaterialFacts>), Error> {
    input.metadata.validate()?;
    if input.common_name.is_empty()
        || input.common_name.len() > 256
        || input.organization.len() > 256
        || input.common_name.contains('\0')
        || input.organization.contains('\0')
        || input.days > 36500
    {
        return Err(Error::Malformed);
    }
    let san = san(input)?;
    if input.profile == Profile::ScepTemplate {
        if input.issuer.is_some() {
            return Err(Error::Malformed);
        }
        let url = input.scep_url.as_ref().ok_or(Error::Malformed)?;
        let parsed = url::Url::parse(url).map_err(|_| Error::Malformed)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::Malformed);
        }
        let value = serde_json::json!({"kind":"scep_request_template","serverURL":url,"subject":{"CN":input.common_name,"O":input.organization},"algorithm":input.algorithm,"challenge":"SUPPLIED_BY_REGISTRATION_SERVICE","caTrust":"SELECT_APPROVED_CA_CERTIFICATE","windows":"Use ClientCertificateInstall CSP SCEP with Atomic; request a device key","macOS":"Use com.apple.security.scep; choose service-accessible device identity","notice":"Template only; no enrollment authorization or device private key is generated"});
        let bytes = serde_json::to_vec_pretty(&value).map_err(|_| Error::Malformed)?;
        return crate::materials::parse(&[file("scep-request.json", Format::Opaque, bytes)]);
    }
    if input.profile == Profile::ApnsCsr
        && (input.algorithm != Algorithm::Rsa2048 || !input.sans.is_empty())
    {
        return Err(Error::Malformed);
    }
    if input.profile != Profile::Https && input.issuer.is_some() {
        return Err(Error::Malformed);
    }
    let private = key(input.algorithm)?;
    let mut name = X509NameBuilder::new().map_err(invalid)?;
    name.append_entry_by_nid(Nid::COMMONNAME, &input.common_name)
        .map_err(invalid)?;
    if !input.organization.is_empty() {
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, &input.organization)
            .map_err(invalid)?;
    }
    let name = name.build();
    let mut csr = X509Req::builder().map_err(invalid)?;
    csr.set_version(0).map_err(invalid)?;
    csr.set_subject_name(&name).map_err(invalid)?;
    csr.set_pubkey(&private).map_err(invalid)?;
    if !input.sans.is_empty() {
        let mut exts = Stack::new().map_err(invalid)?;
        exts.push(san.build(&csr.x509v3_context(None)).map_err(invalid)?)
            .map_err(invalid)?;
        csr.add_extensions(&exts).map_err(invalid)?;
    }
    csr.sign(&private, MessageDigest::sha256())
        .map_err(invalid)?;
    let csr = csr.build();
    let mut files = vec![
        file("request.csr", Format::Csr, csr.to_pem().map_err(invalid)?),
        file(
            "private-key.der",
            Format::PrivateKey,
            private.private_key_to_pkcs8().map_err(invalid)?,
        ),
    ];
    if matches!(input.profile, Profile::Csr | Profile::ApnsCsr) {
        return crate::materials::parse(&files);
    }
    let days = if input.days == 0 {
        if input.profile == Profile::Ca {
            3650
        } else {
            365
        }
    } else {
        input.days
    };
    let until = now
        .checked_add(i64::from(days) * 86400)
        .ok_or(Error::Malformed)?;
    let authority = if input.profile == Profile::Https {
        if input.sans.is_empty() {
            return Err(Error::Malformed);
        }
        Some(issuer(issuer_material.ok_or(Error::Malformed)?, now)?)
    } else {
        None
    };
    if let Some((cert, _)) = &authority
        && until > crate::materials::facts(cert)?.not_after
    {
        return Err(Error::Malformed);
    }
    let mut cert = X509::builder().map_err(invalid)?;
    cert.set_version(2).map_err(invalid)?;
    let mut serial = crate::protection::random::<20>()?;
    serial[0] &= 0x7f;
    serial[0] |= 1;
    let serial = BigNum::from_slice(&serial)
        .and_then(|v| v.to_asn1_integer())
        .map_err(invalid)?;
    cert.set_serial_number(&serial).map_err(invalid)?;
    cert.set_subject_name(&name).map_err(invalid)?;
    cert.set_pubkey(&private).map_err(invalid)?;
    cert.set_issuer_name(
        authority
            .as_ref()
            .map(|(c, _)| c.subject_name())
            .unwrap_or(&name),
    )
    .map_err(invalid)?;
    let from = Asn1Time::from_unix(now).map_err(invalid)?;
    cert.set_not_before(&from).map_err(invalid)?;
    let to = Asn1Time::from_unix(until).map_err(invalid)?;
    cert.set_not_after(&to).map_err(invalid)?;
    let constraints = if input.profile == Profile::Ca {
        BasicConstraints::new().critical().ca().build()
    } else {
        BasicConstraints::new().critical().build()
    }
    .map_err(invalid)?;
    cert.append_extension(constraints).map_err(invalid)?;
    let usage = if input.profile == Profile::Ca {
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
    } else {
        KeyUsage::new().critical().digital_signature().build()
    }
    .map_err(invalid)?;
    cert.append_extension(usage).map_err(invalid)?;
    let ski = SubjectKeyIdentifier::new()
        .build(&cert.x509v3_context(authority.as_ref().map(|(c, _)| c.as_ref()), None))
        .map_err(invalid)?;
    cert.append_extension(ski).map_err(invalid)?;
    if input.profile == Profile::Https {
        cert.append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .build()
                .map_err(invalid)?,
        )
        .map_err(invalid)?;
        let san = san
            .build(&cert.x509v3_context(authority.as_ref().map(|(c, _)| c.as_ref()), None))
            .map_err(invalid)?;
        cert.append_extension(san).map_err(invalid)?;
        let aki = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(true)
            .build(&cert.x509v3_context(authority.as_ref().map(|(c, _)| c.as_ref()), None))
            .map_err(invalid)?;
        cert.append_extension(aki).map_err(invalid)?;
    }
    cert.sign(
        authority.as_ref().map(|(_, k)| k).unwrap_or(&private),
        MessageDigest::sha256(),
    )
    .map_err(invalid)?;
    files.push(file(
        "certificate.pem",
        Format::Certificate,
        cert.build().to_pem().map_err(invalid)?,
    ));
    if let Some((cert, _)) = authority {
        files.push(file(
            "issuer.pem",
            Format::Certificate,
            cert.to_pem().map_err(invalid)?,
        ));
    }
    crate::materials::parse(&files)
}
