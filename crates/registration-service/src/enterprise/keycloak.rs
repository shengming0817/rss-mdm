//! Keycloak 26.7.3 administrative effects, separate from password verification and browser sessions.
//! ref: https://www.keycloak.org/docs-api/26.7.3/rest-api/index.html#_users
use crate::{Error, device_access::lifecycle::IdpAction};
use serde::Deserialize;
use std::{net::SocketAddr, time::Duration};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub provider: Uuid,
    pub issuer: String,
    pub client_id: String,
    pub addresses: Vec<SocketAddr>,
}
pub struct Administrator {
    pub provider: Uuid,
    fingerprint: String,
    client: reqwest::Client,
    issuer: url::Url,
    realm: String,
    client_id: String,
    secret: Zeroizing<String>,
}
#[derive(Deserialize)]
struct Token {
    access_token: String,
    token_type: String,
    expires_in: u64,
}
impl Drop for Token {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}
#[derive(Deserialize)]
struct User {
    id: String,
    enabled: bool,
}
#[derive(Deserialize)]
struct Session {
    id: String,
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub account_disabled: bool,
    pub sessions_revoked: bool,
}
impl Administrator {
    pub fn new(
        config: Configuration,
        secret: Zeroizing<String>,
        ca: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let issuer = url::Url::parse(&config.issuer).map_err(|_| Error::Configuration)?;
        let segments = issuer
            .path_segments()
            .ok_or(Error::Configuration)?
            .collect::<Vec<_>>();
        if config.provider.is_nil()
            || issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || segments.len() != 2
            || segments[0] != "realms"
            || segments[1].is_empty()
            || !segments[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || config.client_id.is_empty()
            || config.client_id.len() > 256
            || secret.is_empty()
            || secret.len() > 4096
            || config.addresses.is_empty()
            || config.addresses.len() > 16
            || config.addresses.iter().any(|a| {
                a.port() != issuer.port_or_known_default().unwrap_or(443)
                    || a.ip().is_unspecified()
                    || a.ip().is_multicast()
            })
        {
            return Err(Error::Configuration);
        }
        let realm = segments[1].to_owned();
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .resolve_to_addrs(
                issuer.host_str().ok_or(Error::Configuration)?,
                &config.addresses,
            );
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(ca).map_err(|_| Error::Configuration)?,
            );
        }
        use sha2::{Digest, Sha256};
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    config.provider,
                    &config.issuer,
                    &config.client_id,
                    &config.addresses
                ))
                .map_err(|_| Error::Configuration)?
            )
        );
        Ok(Self {
            provider: config.provider,
            fingerprint,
            client: builder.build().map_err(|_| Error::Configuration)?,
            issuer,
            realm,
            client_id: config.client_id,
            secret,
        })
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    fn user_url(&self, subject: &str, suffix: Option<&str>) -> Result<url::Url, Error> {
        if subject.is_empty() || subject.len() > 512 || subject.chars().any(char::is_control) {
            return Err(Error::Malformed);
        }
        let mut url = self.issuer.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| Error::Configuration)?;
            segments
                .clear()
                .extend(["admin", "realms", &self.realm, "users", subject]);
            if let Some(suffix) = suffix {
                segments.push(suffix);
            }
        }
        Ok(url)
    }
    async fn token(&self) -> Result<Token, Error> {
        let response = self
            .client
            .post(format!(
                "{}/protocol/openid-connect/token",
                self.issuer.as_str()
            ))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.secret.as_str()),
            ])
            .send()
            .await
            .map_err(|_| Error::Runtime)?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(Error::Unauthorized);
        }
        if !response.status().is_success() {
            return Err(Error::Runtime);
        }
        let bytes = bounded(response).await?;
        let token: Token = serde_json::from_slice(&bytes).map_err(|_| Error::Runtime)?;
        if token.access_token.is_empty()
            || token.access_token.len() > 32768
            || !token.token_type.eq_ignore_ascii_case("bearer")
            || token.expires_in == 0
        {
            return Err(Error::Runtime);
        }
        Ok(token)
    }
    /// Observe both required effects. An absent user is not silently called a successful logout.
    pub async fn observe(&self, subject: &str) -> Result<Observation, Error> {
        tokio::time::timeout(Duration::from_secs(8), self.observe_inner(subject))
            .await
            .unwrap_or(Err(Error::Runtime))
    }
    async fn observe_inner(&self, subject: &str) -> Result<Observation, Error> {
        let token = self.token().await?;
        let response = self
            .client
            .get(self.user_url(subject, None)?)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|_| Error::Runtime)?;
        check(&response)?;
        let user: User =
            serde_json::from_slice(&bounded(response).await?).map_err(|_| Error::Runtime)?;
        if user.id != subject {
            return Err(Error::Forbidden);
        }
        let response = self
            .client
            .get(self.user_url(subject, Some("sessions"))?)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|_| Error::Runtime)?;
        check(&response)?;
        let sessions: Vec<Session> =
            serde_json::from_slice(&bounded(response).await?).map_err(|_| Error::Runtime)?;
        if sessions.iter().any(|s| s.id.is_empty() || s.id.len() > 512) {
            return Err(Error::Runtime);
        }
        Ok(Observation {
            account_disabled: !user.enabled,
            sessions_revoked: sessions.is_empty(),
        })
    }
    /// Exactly one external mutation; caller journals Executing first and reconciles uncertainty.
    pub async fn execute(&self, subject: &str, action: IdpAction) -> Result<(), Error> {
        tokio::time::timeout(Duration::from_secs(8), self.execute_inner(subject, action))
            .await
            .unwrap_or(Err(Error::CommitUnknown))
    }
    async fn execute_inner(&self, subject: &str, action: IdpAction) -> Result<(), Error> {
        let token = self.token().await?;
        let request = match action {
            IdpAction::DisableAccount => self
                .client
                .put(self.user_url(subject, None)?)
                .json(&serde_json::json!({"enabled":false})),
            IdpAction::RevokeSessions => self.client.post(self.user_url(subject, Some("logout"))?),
        };
        let response = request
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|_| Error::CommitUnknown)?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(Error::Unauthorized);
        }
        if response.status().is_server_error() {
            return Err(Error::CommitUnknown);
        }
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
fn check(response: &reqwest::Response) -> Result<(), Error> {
    if matches!(response.status().as_u16(), 401 | 403) {
        Err(Error::Unauthorized)
    } else if !response.status().is_success() {
        Err(Error::Runtime)
    } else {
        Ok(())
    }
}
async fn bounded(mut response: reqwest::Response) -> Result<Zeroizing<Vec<u8>>, Error> {
    if response.content_length().is_some_and(|len| len > 65536) {
        return Err(Error::Capacity);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Runtime)? {
        if bytes.len() + chunk.len() > 65536 {
            return Err(Error::Capacity);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
