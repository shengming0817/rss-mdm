//! 固定 step-ca admin 路径与一次 x5c JWT。管理凭据仅存在于部署进程。
//! ref: smallstep/certificates v0.30.2 ca/adminClient.go generateAdminToken。
use crate::installation::{Error, Result};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    sign::Signer,
    x509::X509,
};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;
use zeroize::Zeroizing;
pub(super) struct Client {
    http: reqwest::Client,
    origin: url::Url,
    key: PKey<Private>,
    chain: Vec<String>,
    subject: String,
    kid: String,
}
impl Client {
    pub fn new(input: &super::Profile, now: i64) -> Result<Self> {
        let origin = url::Url::parse(&input.origin).map_err(|_| Error::Input)?;
        let hostname = origin.host_str().ok_or(Error::Input)?.to_owned();
        if origin.scheme() != "https"
            || origin.origin().ascii_serialization() != input.origin
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.port_or_known_default() != Some(input.address.port())
            || input.address.ip().is_unspecified()
            || input.address.ip().is_multicast()
        {
            return Err(Error::Input);
        }
        let roots =
            crate::config::read(&input.tls_root_file, 131072, false).map_err(|_| Error::Input)?;
        let certificate = crate::config::read(&input.administrator_certificate_file, 131072, false)
            .map_err(|_| Error::Input)?;
        let private = crate::config::read(&input.administrator_key_file, 32768, true)
            .map_err(|_| Error::Input)?;
        let key = PKey::private_key_from_pem(&private)
            .or_else(|_| PKey::private_key_from_pkcs8(&private))
            .map_err(|_| Error::Input)?;
        let certificates = X509::stack_from_pem(&certificate).map_err(|_| Error::Input)?;
        if certificates.is_empty()
            || certificates.len() > 8
            || !certificates[0]
                .public_key()
                .map_err(|_| Error::Input)?
                .public_eq(&key)
        {
            return Err(Error::Input);
        }
        let time = openssl::asn1::Asn1Time::from_unix(now).map_err(|_| Error::Input)?;
        if certificates[0].not_before() > time.as_ref()
            || certificates[0].not_after() <= time.as_ref()
        {
            return Err(Error::Input);
        }
        let mut subjects = certificates[0]
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME);
        let subject = subjects
            .next()
            .ok_or(Error::Input)?
            .data()
            .to_string()
            .map_err(|_| Error::Input)?;
        if subjects.next().is_some()
            || subject.is_empty()
            || subject.len() > 256
            || subject.chars().any(char::is_control)
            || subject != input.administrator_subject
        {
            return Err(Error::Input);
        }
        match key.id() {
            Id::RSA if key.bits() >= 2048 && key.bits() <= 4096 => (),
            Id::EC
                if key.ec_key().map_err(|_| Error::Input)?.group().curve_name()
                    == Some(openssl::nid::Nid::X9_62_PRIME256V1) => {}
            _ => return Err(Error::Input),
        }
        let chain = certificates
            .into_iter()
            .map(|c| {
                c.to_der()
                    .map(|b| STANDARD.encode(b))
                    .map_err(|_| Error::Input)
            })
            .collect::<Result<Vec<_>>>()?;
        use sha2::{Digest, Sha256};
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(
            key.public_key_to_der().map_err(|_| Error::Input)?,
        ));
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&hostname, input.address)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        let authorities =
            reqwest::Certificate::from_pem_bundle(&roots).map_err(|_| Error::Input)?;
        if authorities.is_empty() || authorities.len() > 16 {
            return Err(Error::Input);
        }
        for root in authorities {
            builder = builder.add_root_certificate(root);
        }
        Ok(Self {
            http: builder.build().map_err(|_| Error::Input)?,
            origin,
            key,
            chain,
            subject,
            kid,
        })
    }
    fn token(&self, path: &str, now: i64) -> Result<Zeroizing<String>> {
        let algorithm = if self.key.id() == Id::RSA {
            "RS256"
        } else {
            "ES256"
        };
        let header =
            serde_json::json!({"alg":algorithm,"typ":"JWT","kid":self.kid,"x5c":self.chain});
        let payload = serde_json::json!({"iss":"step-admin-client/1.0","sub":self.subject,"aud":self.origin.join(path).map_err(|_|Error::Input)?.as_str(),"iat":now,"nbf":now,"exp":now.checked_add(60).ok_or(Error::Input)?,"jti":format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple())});
        let signing = Zeroizing::new(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| Error::Input)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).map_err(|_| Error::Input)?)
        ));
        let mut signer =
            Signer::new(MessageDigest::sha256(), &self.key).map_err(|_| Error::Input)?;
        signer
            .update(signing.as_bytes())
            .map_err(|_| Error::Input)?;
        let signature = signer.sign_to_vec().map_err(|_| Error::Input)?;
        let signature = if self.key.id() == Id::EC {
            let signature =
                openssl::ecdsa::EcdsaSig::from_der(&signature).map_err(|_| Error::Input)?;
            let mut bytes = signature.r().to_vec_padded(32).map_err(|_| Error::Input)?;
            bytes.extend(signature.s().to_vec_padded(32).map_err(|_| Error::Input)?);
            bytes
        } else {
            signature
        };
        Ok(Zeroizing::new(format!(
            "{}.{}",
            signing.as_str(),
            URL_SAFE_NO_PAD.encode(signature)
        )))
    }
    /// Public CA chain discovery over the same pinned, verified internal TLS connection.
    pub async fn intermediates(&self) -> Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct Chain {
            crts: Vec<String>,
        }
        let mut response = self
            .http
            .get(
                self.origin
                    .join("/intermediates")
                    .map_err(|_| Error::Input)?,
            )
            .send()
            .await
            .map_err(|_| Error::Storage)?;
        if !response.status().is_success() {
            return Err(Error::Storage);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
            if bytes.len() + chunk.len() > 131072 {
                return Err(Error::Input);
            }
            bytes.extend_from_slice(&chunk);
        }
        let chain: Chain = serde_json::from_slice(&bytes).map_err(|_| Error::Input)?;
        if chain.crts.len() != 1 {
            return Err(Error::Input);
        }
        Ok(chain.crts)
    }
    pub async fn get<T: DeserializeOwned>(&self, name: &str, now: i64) -> Result<Option<T>> {
        self.request(
            reqwest::Method::GET,
            &format!("/admin/provisioners/{name}"),
            None::<&()>,
            now,
        )
        .await
    }
    pub async fn create<T: DeserializeOwned>(&self, input: &impl Serialize, now: i64) -> Result<T> {
        self.request(
            reqwest::Method::POST,
            "/admin/provisioners",
            Some(input),
            now,
        )
        .await?
        .ok_or(Error::Storage)
    }
    pub async fn update(&self, name: &str, input: &impl Serialize, now: i64) -> Result<()> {
        self.request::<serde_json::Value, _>(
            reqwest::Method::PUT,
            &format!("/admin/provisioners/{name}"),
            Some(input),
            now,
        )
        .await?;
        Ok(())
    }
    pub async fn update_webhook(
        &self,
        provisioner: &str,
        webhook: &super::wire::Webhook,
        now: i64,
    ) -> Result<super::wire::Webhook> {
        // step-ca deliberately omits the signing secret in PUT responses; authenticate readback.
        self.request::<serde_json::Value, _>(
            reqwest::Method::PUT,
            &format!(
                "/admin/provisioners/{provisioner}/webhooks/{}",
                webhook.name
            ),
            Some(webhook),
            now,
        )
        .await?;
        self.get::<super::wire::Provisioner>(provisioner, now)
            .await?
            .ok_or(Error::Storage)?
            .webhooks
            .into_iter()
            .find(|h| h.name == webhook.name)
            .ok_or(Error::Storage)
    }
    pub async fn webhook<T: DeserializeOwned>(
        &self,
        name: &str,
        input: &impl Serialize,
        now: i64,
    ) -> Result<T> {
        self.request(
            reqwest::Method::POST,
            &format!("/admin/provisioners/{name}/webhooks"),
            Some(input),
            now,
        )
        .await?
        .ok_or(Error::Storage)
    }
    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
        now: i64,
    ) -> Result<Option<T>> {
        if !path.starts_with("/admin/provisioners")
            || path.contains("..")
            || path
                .bytes()
                .any(|v| !v.is_ascii_alphanumeric() && !b"/-_".contains(&v))
        {
            return Err(Error::Input);
        }
        let token = self.token(path, now)?;
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&token).map_err(|_| Error::Input)?;
        authorization.set_sensitive(true);
        let missing = method == reqwest::Method::GET;
        let empty_allowed = method == reqwest::Method::PUT;
        let mut request = self
            .http
            .request(method, self.origin.join(path).map_err(|_| Error::Input)?)
            .header(reqwest::header::AUTHORIZATION, authorization);
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request.send().await.map_err(|_| Error::Storage)?;
        if missing && response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > 2 * 1024 * 1024)
        {
            return Err(Error::Storage);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(Error::Storage);
            }
            bytes.extend_from_slice(&chunk);
        }
        if empty_allowed && bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Error::Input)
    }
}
