//! Fixed Keycloak Direct Access Grant adapter. It neither owns nor issues Identity sessions.
//! ref: keycloak 26.7.3 ResourceOwnerPasswordCredentialsGrantType.java.
use crate::{Error, Failure};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use rss_mdm_registration_service::enterprise::Subject;
use serde::Deserialize;
use std::{net::SocketAddr, time::Duration};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Public provider coordinates. The host loads secrets independently from protected files.
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub id: Uuid,
    pub revision: u64,
    pub issuer: String,
    pub client_id: String,
    /// Explicit host-approved connection addresses; DNS is not consulted by this adapter.
    pub addresses: Vec<SocketAddr>,
}
/// A narrowly configured password verification capability for one tenant and provider.
pub struct Provider {
    pub configuration: Configuration,
    client: reqwest::Client,
    secret: Zeroizing<String>,
}
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}
impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}
#[derive(Deserialize)]
struct Claims {
    sub: String,
    azp: String,
    iat: i64,
    exp: i64,
}
impl Provider {
    pub fn new(
        configuration: Configuration,
        secret: Zeroizing<String>,
        ca: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let url = url::Url::parse(&configuration.issuer).map_err(|_| Error::Malformed)?;
        let host = url.host_str().ok_or(Error::Malformed)?;
        let valid = |s: &str| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control);
        if configuration.id.is_nil()
            || configuration.revision == 0
            || configuration.revision > i64::MAX as u64
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path().ends_with('/')
            || !url.path().starts_with("/realms/")
            || !valid(&configuration.client_id)
            || secret.is_empty()
            || secret.len() > 4096
            || configuration.addresses.is_empty()
            || configuration.addresses.len() > 16
            || configuration.addresses.iter().any(|a| {
                a.port() != url.port_or_known_default().unwrap_or(443)
                    || a.ip().is_unspecified()
                    || a.ip().is_multicast()
            })
        {
            return Err(Error::Malformed);
        }
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .resolve_to_addrs(host, &configuration.addresses);
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(ca).map_err(|_| Error::Malformed)?,
            );
        }
        let client = builder.build().map_err(|_| Error::Malformed)?;
        Ok(Self {
            configuration,
            client,
            secret,
        })
    }
    /// Deployment identity excludes secrets; business subject mappings are versioned by their owner.
    pub fn fingerprint(&self) -> Result<String, Error> {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(&self.configuration).map_err(|_| Error::Malformed)?;
        Ok(super::crypto::encode(&Sha256::digest(bytes)))
    }
    /// Deploy a monotonic provider configuration; an older process cannot reactivate its mapping.
    pub async fn admit_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Result<(), Error> {
        let hash = self.fingerprint()?;
        sqlx::query("INSERT INTO mdm_apple.psso_password_providers(tenant_id,id,revision,fingerprint) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,fingerprint=excluded.fingerprint WHERE mdm_apple.psso_password_providers.revision<excluded.revision")
            .bind(tenant.to_string()).bind(self.configuration.id).bind(self.configuration.revision as i64).bind(hash)
            .execute(&mut *c).await.map_err(crate::database::db)?;
        self.check_on(c, tenant).await
    }
    pub async fn check_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Result<(), Error> {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_apple.psso_password_providers WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3 AND fingerprint=$4)")
            .bind(tenant.to_string()).bind(self.configuration.id).bind(self.configuration.revision as i64).bind(self.fingerprint()?)
            .fetch_one(c).await.map_err(crate::database::db)?;
        if !valid {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// No retries. All network work completes outside the host's SQL transaction.
    pub async fn verify(&self, subject: &Subject, password: &str, now: i64) -> Result<(), Error> {
        if password.is_empty()
            || password.len() > 4096
            || subject.provider != self.configuration.id
            || !subject.enabled
            || subject.revision < 1
        {
            return Err(Error::Unauthorized);
        }
        let response = self
            .client
            .post(format!(
                "{}/protocol/openid-connect/token",
                self.configuration.issuer
            ))
            .form(&[
                ("grant_type", "password"),
                ("client_id", self.configuration.client_id.as_str()),
                ("client_secret", self.secret.as_str()),
                ("username", subject.username.as_str()),
                ("password", password),
                ("scope", "openid"),
            ])
            .send()
            .await
            .map_err(|_| unavailable())?;
        if matches!(response.status().as_u16(), 400 | 401 | 403) {
            return Err(Error::Unauthorized);
        }
        if !response.status().is_success() {
            return Err(unavailable());
        }
        let bytes = bounded(response, 65536).await?;
        let token: TokenResponse = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        if !token.token_type.eq_ignore_ascii_case("bearer") || token.access_token.len() > 32768 {
            return Err(Error::Unauthorized);
        }
        let header =
            jsonwebtoken::decode_header(&token.access_token).map_err(|_| Error::Unauthorized)?;
        if header.alg != Algorithm::RS256 {
            return Err(Error::Unauthorized);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|v| !v.is_empty() && v.len() <= 256)
            .ok_or(Error::Unauthorized)?;
        let response = self
            .client
            .get(format!(
                "{}/protocol/openid-connect/certs",
                self.configuration.issuer
            ))
            .send()
            .await
            .map_err(|_| unavailable())?;
        if !response.status().is_success() {
            return Err(unavailable());
        }
        let keys: JwkSet =
            serde_json::from_slice(&bounded(response, 131072).await?).map_err(|_| unavailable())?;
        if keys.keys.len() > 32 {
            return Err(unavailable());
        }
        let matching = keys
            .keys
            .iter()
            .filter(|k| k.common.key_id.as_deref() == Some(kid))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(Error::Unauthorized);
        }
        let key = DecodingKey::from_jwk(matching[0]).map_err(|_| Error::Unauthorized)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.configuration.issuer]);
        validation.set_audience(&[&self.configuration.client_id]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp"]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        let claims = jsonwebtoken::decode::<Claims>(&token.access_token, &key, &validation)
            .map_err(|_| Error::Unauthorized)?
            .claims;
        if claims.sub != subject.subject
            || claims.azp != self.configuration.client_id
            || claims.iat < now.saturating_sub(5)
            || claims.iat > now.saturating_add(10)
            || claims.exp <= now
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Protocol)
}
async fn bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(unavailable());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
