//! Parse actual cryptographic material; never infer deployment or public trust.
//! ref: rust-openssl openssl/src/pkcs12.rs and openssl/src/x509/mod.rs.
use crate::{model::Bundle, *};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::{PKey, Public},
    x509::{X509, X509NameRef, X509Req},
};
use ring::digest::{SHA256, digest};
use zeroize::Zeroizing;

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn public_id(key: &PKey<Public>) -> Result<String, Error> {
    Ok(hex(digest(
        &SHA256,
        &key.public_key_to_der().map_err(|_| Error::Material)?,
    )
    .as_ref()))
}
fn name(value: &X509NameRef) -> Result<String, Error> {
    value
        .entries()
        .map(|e| {
            Ok(format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("OID"),
                e.data().to_string().map_err(|_| Error::Material)?
            ))
        })
        .collect::<Result<Vec<_>, Error>>()
        .map(|v| v.join(", "))
}
fn seconds(time: &openssl::asn1::Asn1TimeRef) -> Result<i64, Error> {
    let epoch = Asn1Time::from_unix(0).map_err(|_| Error::Material)?;
    let d = epoch.diff(time).map_err(|_| Error::Material)?;
    Ok(i64::from(d.days) * 86400 + i64::from(d.secs))
}
pub(crate) fn facts(cert: &X509) -> Result<CertificateFacts, Error> {
    let key = cert.public_key().map_err(|_| Error::Material)?;
    let sans = cert
        .subject_alt_names()
        .map(|s| {
            s.iter()
                .filter_map(|n| {
                    n.dnsname().map(str::to_owned).or_else(|| {
                        n.ipaddress().and_then(|b| match b.len() {
                            4 => Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
                            16 => Some(
                                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?).to_string(),
                            ),
                            _ => None,
                        })
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(CertificateFacts {
        subject: name(cert.subject_name())?,
        issuer: name(cert.issuer_name())?,
        sans,
        serial: cert
            .serial_number()
            .to_bn()
            .and_then(|n| n.to_hex_str())
            .map_err(|_| Error::Material)?
            .to_string(),
        fingerprint: hex(&cert
            .digest(MessageDigest::sha256())
            .map_err(|_| Error::Material)?),
        algorithm: format!("{:?}/{}", key.id(), key.bits()),
        not_before: seconds(cert.not_before())?,
        not_after: seconds(cert.not_after())?,
        public_key: public_id(&key)?,
    })
}
fn certificates(bytes: &[u8], format: Format) -> Result<Vec<X509>, Error> {
    let certs = if bytes.starts_with(b"-----BEGIN") {
        X509::stack_from_pem(bytes)
    } else {
        X509::from_der(bytes).map(|v| vec![v])
    }
    .map_err(|_| Error::Material)?;
    if certs.is_empty() || certs.len() > 16 || (format == Format::Certificate && certs.len() != 1) {
        return Err(Error::Material);
    }
    Ok(certs)
}
pub(crate) fn parse(files: &[ImportFile]) -> Result<(Bundle, Vec<MaterialFacts>), Error> {
    if files.is_empty() || files.len() > 16 {
        return Err(Error::Malformed);
    }
    let mut total = 0usize;
    let mut bundle = Bundle { files: vec![] };
    let mut values = vec![];
    for file in files {
        if file.name.is_empty()
            || file.name.len() > 128
            || file.name.contains(['/', '\\', '\0'])
            || bundle.files.iter().any(|v| v.name == file.name)
        {
            return Err(Error::Malformed);
        }
        if file.data.len() > MAX_MATERIAL_BYTES.div_ceil(3) * 4 {
            return Err(Error::Malformed);
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(file.data.as_bytes())
                .map_err(|_| Error::Malformed)?,
        );
        total = total.checked_add(bytes.len()).ok_or(Error::Malformed)?;
        if bytes.is_empty() || total > MAX_MATERIAL_BYTES {
            return Err(Error::Malformed);
        }
        if file
            .password
            .as_ref()
            .is_some_and(|p| p.len() > 1024 || p.contains('\0'))
        {
            return Err(Error::Malformed);
        }
        let mut value = MaterialFacts {
            name: file.name.clone(),
            format: file.format,
            certificates: vec![],
            public_keys: vec![],
            contains_private_key: false,
        };
        match file.format {
            Format::Certificate | Format::Chain => {
                value.certificates = certificates(&bytes, file.format)?
                    .iter()
                    .map(facts)
                    .collect::<Result<_, _>>()?;
                value.public_keys = value
                    .certificates
                    .iter()
                    .map(|c| c.public_key.clone())
                    .collect();
            }
            Format::Csr => {
                let csr = if bytes.starts_with(b"-----BEGIN") {
                    X509Req::from_pem(&bytes)
                } else {
                    X509Req::from_der(&bytes)
                }
                .map_err(|_| Error::Material)?;
                let key = csr.public_key().map_err(|_| Error::Material)?;
                if !csr.verify(&key).map_err(|_| Error::Material)? {
                    return Err(Error::Material);
                }
                value.public_keys.push(public_id(&key)?);
            }
            Format::PrivateKey => {
                let key = if bytes.starts_with(b"-----BEGIN") {
                    // An explicit password keeps OpenSSL from consulting the terminal.
                    PKey::private_key_from_pem_passphrase(
                        &bytes,
                        file.password
                            .as_deref()
                            .map(|p| p.as_bytes())
                            .unwrap_or(b""),
                    )
                } else if let Some(p) = &file.password {
                    PKey::private_key_from_pkcs8_passphrase(&bytes, p.as_bytes())
                } else {
                    PKey::private_key_from_der(&bytes)
                }
                .map_err(|_| Error::Material)?;
                let public = PKey::public_key_from_der(
                    &key.public_key_to_der().map_err(|_| Error::Material)?,
                )
                .map_err(|_| Error::Material)?;
                value.public_keys.push(public_id(&public)?);
                value.contains_private_key = true;
                bundle.files.push(ExportFile {
                    name: format!("{}.pk8", file.name),
                    data: Zeroizing::new(STANDARD.encode(Zeroizing::new(
                        key.private_key_to_pkcs8().map_err(|_| Error::Material)?,
                    ))),
                });
            }
            Format::Pkcs12 => {
                let p12 = Pkcs12::from_der(&bytes).map_err(|_| Error::Material)?;
                let parsed = p12
                    .parse2(file.password.as_deref().map(|p| p.as_str()).unwrap_or(""))
                    .map_err(|_| Error::Material)?;
                if let Some(cert) = parsed.cert {
                    value.certificates.push(facts(&cert)?);
                    bundle.files.push(ExportFile {
                        name: format!("{}.cert.pem", file.name),
                        data: Zeroizing::new(
                            STANDARD.encode(cert.to_pem().map_err(|_| Error::Material)?),
                        ),
                    });
                }
                if let Some(chain) = parsed.ca {
                    if chain.len() > 16 {
                        return Err(Error::Material);
                    }
                    for cert in chain {
                        value.certificates.push(facts(&cert)?);
                    }
                }
                if let Some(key) = parsed.pkey {
                    value.contains_private_key = true;
                    let public = PKey::public_key_from_der(
                        &key.public_key_to_der().map_err(|_| Error::Material)?,
                    )
                    .map_err(|_| Error::Material)?;
                    let key_id = public_id(&public)?;
                    if !value.certificates.is_empty() && value.certificates[0].public_key != key_id
                    {
                        return Err(Error::KeyMismatch);
                    }
                    value.public_keys.push(key_id);
                    bundle.files.push(ExportFile {
                        name: format!("{}.key.pk8", file.name),
                        data: Zeroizing::new(STANDARD.encode(Zeroizing::new(
                            key.private_key_to_pkcs8().map_err(|_| Error::Material)?,
                        ))),
                    });
                }
                value
                    .public_keys
                    .extend(value.certificates.iter().map(|c| c.public_key.clone()));
                if value.public_keys.is_empty() {
                    return Err(Error::Material);
                }
            }
            Format::Opaque => {}
        }
        bundle.files.push(ExportFile {
            name: file.name.clone(),
            data: Zeroizing::new(file.data.to_string()),
        });
        values.push(value);
    }
    let cert_keys: Vec<_> = values
        .iter()
        .flat_map(|v| v.certificates.iter().map(|c| &c.public_key))
        .collect();
    for value in &values {
        if (value.contains_private_key || value.format == Format::Csr)
            && !cert_keys.is_empty()
            && value.public_keys.iter().any(|p| !cert_keys.contains(&p))
        {
            return Err(Error::KeyMismatch);
        }
    }
    let mut names = std::collections::HashSet::new();
    if bundle.files.iter().any(|f| !names.insert(&f.name)) {
        return Err(Error::Malformed);
    }
    Ok((bundle, values))
}
pub(crate) fn check_request(
    request: &[MaterialFacts],
    incoming: &[MaterialFacts],
) -> Result<(), Error> {
    let expected: Vec<_> = request
        .iter()
        .filter(|f| f.format == Format::Csr)
        .flat_map(|f| &f.public_keys)
        .collect();
    let leaf = incoming
        .iter()
        .find_map(|f| f.certificates.first())
        .ok_or(Error::KeyMismatch)?;
    if expected.len() != 1 || *expected[0] != leaf.public_key {
        return Err(Error::KeyMismatch);
    }
    Ok(())
}
