//! Device PKI provider. Authorization and activation remain with each lifecycle owner.
//! ref: smallstep/certificates@v0.30.2 api/sign.go, api/revoke.go, authority/provisioner/jwk.go.
pub mod certificates;
pub mod maintenance;
pub mod mutation;
pub mod providers;
pub mod recovery;
pub mod registry;
pub mod scep;
pub mod signing;
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;
use x509_cert::der::{DecodePem, Encode};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PKI configuration rejected")]
    Configuration,
    #[error("PKI request rejected before dispatch")]
    Request,
    #[error("PKI state conflict")]
    Conflict,
    #[error("PKI permission rejected")]
    Forbidden,
    #[error("PKI persistence unavailable")]
    Storage,
    #[error("PKI audit failure")]
    Audit(#[from] rss_mdm_audit_integration::Error),
    #[error("PKI operation result unknown")]
    Unknown { attempt: Uuid },
}
pub struct Configuration {
    pub origin: String,
    pub provisioner: String,
    pub kid: String,
}
/// One explicitly configured step-ca issuer; no provider fallback or local CA key.
pub struct StepCa {
    client: reqwest::Client,
    origin: url::Url,
    key: signature::RsaKeyPair,
    provisioner: String,
    kid: String,
}
/// Supplied only after the lifecycle owner has durably frozen its authorization.
#[derive(Clone, Copy)]
pub struct Sign<'a> {
    pub attempt: Uuid,
    pub csr_pem: &'a str,
    pub csr_digest: &'a [u8; 32],
    pub subject: &'a str,
    pub sans: &'a [String],
    pub start: i64,
    pub end: i64,
    pub deadline: i64,
}
impl StepCa {
    pub fn new(config: Configuration, tls_root: &[u8], pkcs8: &[u8]) -> Result<Self, Error> {
        Self::connect(config, tls_root, pkcs8, None)
    }
    /// Deployment qualification pins the approved peer while preserving TLS hostname verification.
    pub fn at_address(
        config: Configuration,
        tls_root: &[u8],
        pkcs8: &[u8],
        address: std::net::SocketAddr,
    ) -> Result<Self, Error> {
        Self::connect(config, tls_root, pkcs8, Some(address))
    }
    fn connect(
        config: Configuration,
        tls_root: &[u8],
        pkcs8: &[u8],
        address: Option<std::net::SocketAddr>,
    ) -> Result<Self, Error> {
        let invalid = || Error::Configuration;
        let origin = url::Url::parse(&config.origin).map_err(|_| invalid())?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || config.kid.is_empty()
            || config.kid.len() > 128
            || config.provisioner.is_empty()
            || config.provisioner.len() > 128
            || pkcs8.len() > 32768
            || tls_root.len() > 131072
        {
            return Err(invalid());
        }
        let key = signature::RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| invalid())?;
        let mut client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(tls_root).map_err(|_| invalid())?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8));
        if let Some(address) = address {
            if origin.port_or_known_default() != Some(address.port())
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
            {
                return Err(invalid());
            }
            client = client.resolve(origin.host_str().ok_or_else(invalid)?, address);
        }
        let client = client.build().map_err(|_| invalid())?;
        Ok(Self {
            client,
            origin,
            key,
            provisioner: config.provisioner,
            kid: config.kid,
        })
    }
    /// Public identity, suitable for immutable issuance records; contains no private material.
    pub fn authority_digest(&self, issuer_digest: &str) -> String {
        let bytes = serde_json::to_vec(&(
            "device-pki/v1",
            issuer_digest,
            self.origin.as_str(),
            &self.provisioner,
            &self.kid,
            URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref()),
        ))
        .expect("scalar authority identity");
        format!("{:x}", Sha256::digest(bytes))
    }
    fn url(&self, path: &str) -> url::Url {
        let mut url = self.origin.clone();
        url.set_path(path);
        url
    }
    fn token(
        &self,
        path: &str,
        attempt: Uuid,
        subject: &str,
        sans: &[String],
        csr_digest: Option<&[u8; 32]>,
        validity: std::ops::Range<i64>,
    ) -> Result<Zeroizing<String>, Error> {
        let now = validity.start;
        let deadline = validity.end;
        let unknown = || Error::Unknown { attempt };
        let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":self.kid});
        let mut payload = serde_json::json!({"iss":self.provisioner,"aud":[self.url(path).as_str()],
            "sub":subject,"iat":now,"nbf":now,"exp":deadline.min(now+60),"jti":attempt.to_string()});
        if let Some(digest) = csr_digest {
            payload["sans"] = serde_json::json!(sans);
            payload["cnf"] = serde_json::json!({"x5rt#S256":URL_SAFE_NO_PAD.encode(digest)});
        }
        let message = Zeroizing::new(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| unknown())?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).map_err(|_| unknown())?)
        ));
        let mut sig = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut sig,
            )
            .map_err(|_| unknown())?;
        Ok(Zeroizing::new(format!(
            "{}.{}",
            message.as_str(),
            URL_SAFE_NO_PAD.encode(sig)
        )))
    }
    /// ref: smallstep/certificates v0.30.2 api/api.go IntermediatesResponse.
    /// Check the actual CA issuer before a generation can authorize new signing.
    /// 导入前核对真实 CA 的公开 JWK；不需要或接收管理凭据。
    pub async fn verify_provisioner(&self) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Jwk {
            kty: String,
            kid: Option<String>,
            n: Option<String>,
            e: Option<String>,
        }
        #[derive(Deserialize)]
        struct Provisioner {
            #[serde(rename = "type")]
            kind: String,
            name: String,
            key: Option<Jwk>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Page {
            provisioners: Vec<Provisioner>,
            #[serde(default)]
            next_cursor: String,
        }
        let mut cursor = String::new();
        for _ in 0..16 {
            let mut url = self.url("/provisioners");
            if !cursor.is_empty() {
                url.query_pairs_mut().append_pair("cursor", &cursor);
            }
            let mut response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|_| Error::Storage)?;
            if !response.status().is_success()
                || response.content_length().is_some_and(|n| n > 131072)
            {
                return Err(Error::Storage);
            }
            let mut body = zeroize::Zeroizing::new(Vec::new());
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
                if body.len() + chunk.len() > 131072 {
                    return Err(Error::Storage);
                }
                body.extend_from_slice(&chunk);
            }
            let page: Page = serde_json::from_slice(&body).map_err(|_| Error::Configuration)?;
            for provider in page.provisioners {
                if provider.name != self.provisioner {
                    continue;
                }
                let key = provider.key.ok_or(Error::Configuration)?;
                if provider.kind != "JWK"
                    || key.kty != "RSA"
                    || key.kid.as_deref() != Some(&self.kid)
                {
                    return Err(Error::Configuration);
                }
                let n = URL_SAFE_NO_PAD
                    .decode(key.n.ok_or(Error::Configuration)?)
                    .map_err(|_| Error::Configuration)?;
                let e = URL_SAFE_NO_PAD
                    .decode(key.e.ok_or(Error::Configuration)?)
                    .map_err(|_| Error::Configuration)?;
                if n.len() < 256 || n.len() > 512 || e.is_empty() || e.len() > 8 {
                    return Err(Error::Configuration);
                }
                let public = openssl::rsa::Rsa::from_public_components(
                    openssl::bn::BigNum::from_slice(&n).map_err(|_| Error::Configuration)?,
                    openssl::bn::BigNum::from_slice(&e).map_err(|_| Error::Configuration)?,
                )
                .map_err(|_| Error::Configuration)?;
                if public
                    .public_key_to_der_pkcs1()
                    .map_err(|_| Error::Configuration)?
                    .as_slice()
                    != self.key.public_key().as_ref()
                {
                    return Err(Error::Configuration);
                }
                return Ok(());
            }
            if page.next_cursor.is_empty() || page.next_cursor == cursor {
                return Err(Error::Configuration);
            }
            if page.next_cursor.len() > 1024 {
                return Err(Error::Configuration);
            }
            cursor = page.next_cursor;
        }
        Err(Error::Configuration)
    }
    pub async fn verify_issuer(&self, expected: &str) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Intermediates {
            crts: Vec<String>,
        }
        let mut response = self
            .client
            .get(self.url("/intermediates"))
            .send()
            .await
            .map_err(|_| Error::Storage)?;
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > 131072)
        {
            return Err(Error::Storage);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
            if bytes.len() + chunk.len() > 131072 {
                return Err(Error::Storage);
            }
            bytes.extend_from_slice(&chunk);
        }
        let result: Intermediates =
            serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
        if result.crts.len() != 1 {
            return Err(Error::Configuration);
        }
        let certificate =
            x509_cert::Certificate::from_pem(&result.crts[0]).map_err(|_| Error::Configuration)?;
        if rss_mdm_device_trust::digest(&certificate.to_der().map_err(|_| Error::Configuration)?)
            != expected
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Fixed configured origin only; no redirects, proxies or caller supplied URL.
    pub async fn published_crl(&self) -> Result<Vec<u8>, Error> {
        let mut response = self
            .client
            .get(self.url("/crl"))
            .send()
            .await
            .map_err(|_| Error::Storage)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > 16 * 1024 * 1024)
        {
            return Err(Error::Storage);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
            if bytes.len() + chunk.len() > 16 * 1024 * 1024 {
                return Err(Error::Storage);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    async fn post(
        &self,
        path: &str,
        attempt: Uuid,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        let unknown = || Error::Unknown { attempt };
        let mut response = self
            .client
            .post(self.url(path))
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| unknown())?;
        // A used token or error response cannot prove no certificate/revocation exists.
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > 131072)
        {
            return Err(unknown());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unknown())? {
            if bytes.len() + chunk.len() > 131072 {
                return Err(unknown());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    pub async fn sign(&self, intent: Sign<'_>, now: i64) -> Result<Vec<Vec<u8>>, Error> {
        if now <= 0
            || now < intent.start
            || now >= intent.deadline
            || now - intent.start >= 60
            || intent.end <= intent.start
            || intent.subject.is_empty()
            || intent.subject.len() > 256
            || intent.csr_pem.len() > 65536
            || intent.sans.len() > 8
        {
            return Err(Error::Request);
        }
        let unknown = || Error::Unknown {
            attempt: intent.attempt,
        };
        // Windows templates emit only the lifecycle owner's subject and no SANs. JWK's
        // pre-template CSR validator still requires its input names in the signed token.
        // They remain bound to the frozen CSR fingerprint; they do not authorize leaf identity.
        // ref: smallstep/certificates v0.30.2 authority/provisioner/jwk.go AuthorizeSign.
        let csr_names;
        let token_names = if intent.sans.is_empty() {
            csr_names = csr_input_names(intent.csr_pem)?;
            csr_names.as_slice()
        } else {
            intent.sans
        };
        let token = self.token(
            "/sign",
            intent.attempt,
            intent.subject,
            token_names,
            Some(intent.csr_digest),
            now..intent.deadline,
        )?;
        let timestamp = |value| {
            time::OffsetDateTime::from_unix_timestamp(value)
                .ok()
                .and_then(|t| {
                    t.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                })
                .ok_or_else(unknown)
        };
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a> {
            csr: &'a str,
            ott: &'a str,
            not_before: String,
            not_after: String,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Request {
                csr: intent.csr_pem,
                ott: &token,
                not_before: timestamp(intent.start)?,
                not_after: timestamp(intent.end)?,
            })
            .map_err(|_| unknown())?,
        );
        let bytes = self.post("/sign", intent.attempt, body).await?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            crt: String,
            cert_chain: Vec<String>,
        }
        let response: Response = serde_json::from_slice(&bytes).map_err(|_| unknown())?;
        if response.cert_chain.is_empty()
            || response.cert_chain.len() > 4
            || response.cert_chain[0] != response.crt
        {
            return Err(unknown());
        }
        response
            .cert_chain
            .iter()
            .map(|pem| {
                x509_cert::Certificate::from_pem(pem)
                    .and_then(|c| c.to_der())
                    .map_err(|_| unknown())
            })
            .collect()
    }
    /// Passive is mandatory in upstream v0.30.2, including when CRL generation is enabled.
    /// This acknowledgment is NOT proof that the serial is present in a published CRL.
    pub async fn revoke(&self, attempt: Uuid, serial: &str, now: i64) -> Result<(), Error> {
        if now <= 0
            || serial.is_empty()
            || serial.len() > 128
            || !serial.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Request);
        }
        let token = self.token("/revoke", attempt, serial, &[], None, now..now + 60)?;
        let body = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({"serial":serial,
            "ott":token.as_str(),"passive":true,"reasonCode":0,"reason":"device identity revoked"}))
            .map_err(|_| Error::Unknown { attempt })?,
        );
        self.post("/revoke", attempt, body).await.map(|_| ())
    }
}

/// Names admitted to the CA's input validator, never copied by the Windows leaf template.
fn csr_input_names(pem: &str) -> Result<Vec<String>, Error> {
    use x509_cert::{
        der::Decode,
        ext::pkix::{SubjectAltName, name::GeneralName},
        request::CertReq,
    };
    let request = CertReq::from_pem(pem).map_err(|_| Error::Request)?;
    let mut names = Vec::new();
    for rdn in &request.info.subject.0 {
        for attribute in rdn.0.iter() {
            if attribute.oid.to_string() == "2.5.4.3" {
                names.push(
                    std::str::from_utf8(attribute.value.value())
                        .map_err(|_| Error::Request)?
                        .to_owned(),
                );
            }
        }
    }
    for attribute in request.info.attributes.iter() {
        if attribute.oid.to_string() != "1.2.840.113549.1.9.14" {
            continue;
        }
        for value in attribute.values.iter() {
            let extensions: Vec<x509_cert::ext::Extension> =
                value.decode_as().map_err(|_| Error::Request)?;
            for extension in extensions {
                if extension.extn_id.to_string() != "2.5.29.17" {
                    continue;
                }
                let sans = SubjectAltName::from_der(extension.extn_value.as_bytes())
                    .map_err(|_| Error::Request)?;
                for name in sans.0 {
                    names.push(match name {
                        GeneralName::DnsName(v)
                        | GeneralName::Rfc822Name(v)
                        | GeneralName::UniformResourceIdentifier(v) => v.as_str().to_owned(),
                        GeneralName::IpAddress(v) => match v.as_bytes() {
                            bytes if bytes.len() == 4 => std::net::Ipv4Addr::from(
                                <[u8; 4]>::try_from(bytes).map_err(|_| Error::Request)?,
                            )
                            .to_string(),
                            bytes if bytes.len() == 16 => std::net::Ipv6Addr::from(
                                <[u8; 16]>::try_from(bytes).map_err(|_| Error::Request)?,
                            )
                            .to_string(),
                            _ => return Err(Error::Request),
                        },
                        _ => return Err(Error::Request),
                    });
                }
            }
        }
    }
    names.sort();
    names.dedup();
    if names.len() > 16
        || names
            .iter()
            .any(|s| s.len() > 256 || s.chars().any(char::is_control))
    {
        return Err(Error::Request);
    }
    Ok(names)
}
