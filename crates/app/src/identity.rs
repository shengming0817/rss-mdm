//! Standard OIDC client plus the sole upstream online verifier.
use crate::{ConfigIssue, Failure};
use crate::{
    Error,
    config::{self, Config},
    sessions::{Lease, Pending, Session, random},
};
use openidconnect::{core::*, *};
use rss_identity_client::{ClientConfig, Clock, IdentityClient, VerifiedIdentity};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

type Oidc = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
fn verifier(client: &Oidc) -> CoreIdTokenVerifier<'_> {
    client
        .id_token_verifier()
        .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256])
}
fn transport(error: reqwest::Error) -> Error {
    Error::Unavailable(if error.is_timeout() {
        Failure::IdentityDeadline
    } else {
        Failure::IdentityTransport
    })
}
struct Http {
    client: reqwest::Client,
    origin: url::Origin,
}
impl Http {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let url = url::Url::parse(&request.uri().to_string())
            .map_err(|_| Error::Unavailable(Failure::IdentityProtocol))?;
        if url.origin() != self.origin
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Unavailable(Failure::IdentityProtocol));
        }
        let mut response = self
            .client
            .request(request.method().clone(), url)
            .headers(request.headers().clone())
            .body(request.into_body())
            .send()
            .await
            .map_err(transport)?;
        let mut builder = axum::http::Response::builder().status(response.status());
        *builder
            .headers_mut()
            .ok_or(Error::Unavailable(Failure::IdentityProtocol))? = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if bytes.len() + chunk.len() > 65536 {
                return Err(Error::Unavailable(Failure::IdentityProtocol));
            }
            bytes.extend_from_slice(&chunk);
        }
        builder
            .body(bytes)
            .map_err(|_| Error::Unavailable(Failure::IdentityProtocol))
    }
}
impl<'c> AsyncHttpClient<'c> for Http {
    type Error = Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<HttpResponse, Error>> + Send + 'c>,
    >;
    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.request(request))
    }
}
pub(crate) struct Identity {
    oidc: Oidc,
    http: Http,
    online: IdentityClient,
    audience: String,
    issuer: String,
}
impl Identity {
    pub async fn connect(c: &Config, clock: Arc<dyn Clock>) -> Result<Self, Error> {
        let oidc_secret = config::secret(&c.identity.oidc_secret_file)
            .map_err(|_| Error::Configuration(ConfigIssue::OidcSecret))?;
        let validation = config::secret(&c.identity.validation_secret_file)
            .map_err(|_| Error::Configuration(ConfigIssue::ValidationSecret))?;
        if crate::sessions::equal(&oidc_secret, &validation) {
            return Err(Error::Configuration(ConfigIssue::DistinctSecrets));
        }
        let ca = config::read(&c.identity.ca_file, 1024 * 1024, false)
            .map_err(|_| Error::Configuration(ConfigIssue::IdentityCa))?;
        let http = Http {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .add_root_certificate(
                    reqwest::Certificate::from_pem(&ca)
                        .map_err(|_| Error::Configuration(ConfigIssue::IdentityCa))?,
                )
                .build()
                .map_err(|_| Error::Configuration(ConfigIssue::IdentityClient))?,
            origin: config::https_url(&c.identity.issuer)?.origin(),
        };
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(c.identity.issuer.clone())
                .map_err(|_| Error::Configuration(ConfigIssue::IdentityClient))?,
            &http,
        )
        .await
        .map_err(|error| match error {
            DiscoveryError::Request(error) => error,
            _ => Error::Unavailable(Failure::IdentityProtocol),
        })?;
        for endpoint in [
            Some(metadata.authorization_endpoint().url()),
            metadata.token_endpoint().map(|u| u.url()),
            Some(metadata.jwks_uri().url()),
        ] {
            if !endpoint.is_some_and(|u| u.origin() == http.origin && u.scheme() == "https") {
                return Err(Error::Configuration(ConfigIssue::OidcEndpoints));
            }
        }
        if !metadata
            .id_token_signing_alg_values_supported()
            .contains(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256)
            || metadata
                .id_token_signing_alg_values_supported()
                .iter()
                .any(|alg| {
                    matches!(
                        alg,
                        CoreJwsSigningAlgorithm::HmacSha256
                            | CoreJwsSigningAlgorithm::HmacSha384
                            | CoreJwsSigningAlgorithm::HmacSha512
                            | CoreJwsSigningAlgorithm::None
                    )
                })
        {
            return Err(Error::Configuration(ConfigIssue::OidcAlgorithms));
        }
        let oidc = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(c.identity.client_id.clone()),
            Some(ClientSecret::new(oidc_secret.to_string())),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/auth/callback", c.product_origin))
                .map_err(|_| Error::Configuration(ConfigIssue::IdentityClient))?,
        );
        let online = IdentityClient::new(
            ClientConfig {
                identity_origin: c.identity.origin.clone(),
                issuer: c.identity.issuer.clone(),
                client_id: c.identity.client_id.clone(),
                validation_secret: validation,
                tenant_id: c.identity.tenant_id.clone(),
                audience: c.identity.audience.clone(),
                timeout: Duration::from_secs(5),
                ca_pem: Some(ca.to_vec()),
            },
            clock,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::IdentityClient))?;
        Ok(Self {
            oidc,
            http,
            online,
            audience: c.identity.audience.clone(),
            issuer: c.identity.issuer.clone(),
        })
    }
    pub fn is_issuer(&self, issuer: &str) -> bool {
        self.issuer == issuer
    }
    pub fn begin(
        &self,
        browser: String,
        old_session: Option<String>,
        now: i64,
    ) -> (String, String, Pending) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = self
            .oidc
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .add_extra_param("audience", &self.audience)
            .url();
        (
            url.to_string(),
            state.secret().clone(),
            Pending {
                browser,
                old_session,
                nonce,
                verifier,
                expires: now + 300,
            },
        )
    }
    pub async fn finish(&self, code: String, pending: Pending) -> Result<Session, Error> {
        let response = self
            .oidc
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| Error::Configuration(ConfigIssue::IdentityClient))?
            .set_pkce_verifier(pending.verifier)
            .request_async(&self.http)
            .await
            .map_err(|error| match error {
                RequestTokenError::ServerResponse(response)
                    if matches!(response.error(), CoreErrorResponseType::InvalidGrant) =>
                {
                    Error::Unauthorized
                }
                RequestTokenError::Request(error) => error,
                RequestTokenError::ServerResponse(_) => Error::Unavailable(Failure::IdentityServer),
                _ => Error::Unavailable(Failure::IdentityProtocol),
            })?;
        let id = response.id_token().ok_or(Error::Unauthorized)?;
        let verifier = verifier(&self.oidc);
        let claims = id
            .claims(&verifier, &pending.nonce)
            .map_err(|_| Error::Unauthorized)?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                id.signing_alg().map_err(|_| Error::Unauthorized)?,
                id.signing_key(&verifier).map_err(|_| Error::Unauthorized)?,
            )
            .map_err(|_| Error::Unauthorized)?;
            if actual != *expected {
                return Err(Error::Unauthorized);
            }
        }
        let proof = self
            .online
            .validate(response.access_token().secret())
            .await
            .map_err(map_error)?;
        if proof.subject() != claims.subject().as_str() {
            return Err(Error::Unauthorized);
        }
        Ok(Session {
            credential: Zeroizing::new(response.access_token().secret().clone()),
            subject: proof.subject().into(),
            identity_session: proof.session_id().into(),
            csrf: random(),
            expires: proof.expires_at(),
        })
    }
    pub async fn validate(&self, lease: &Lease) -> Result<VerifiedIdentity, Error> {
        let proof = self
            .online
            .validate(&lease.credential)
            .await
            .map_err(map_error)?;
        if proof.subject() != lease.subject || proof.session_id() != lease.identity_session {
            return Err(Error::Unauthorized);
        }
        Ok(proof)
    }
}
fn map_error(error: rss_identity_client::Error) -> Error {
    use rss_identity_client::Error as E;
    match error {
        E::Rejected => Error::Unauthorized,
        E::Server {
            code,
            correlation_id,
        } => Error::IdentityServer {
            code,
            correlation_id,
        },
        E::Unavailable => Error::Unavailable(Failure::IdentityValidation),
        E::Invalid => Error::Unavailable(Failure::IdentityProtocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    #[test]
    fn discovery_cannot_enable_client_secret_or_unsigned_id_tokens() {
        let metadata:CoreProviderMetadata=serde_json::from_value(serde_json::json!({
            "issuer":"https://identity.example.test", "authorization_endpoint":"https://identity.example.test/auth",
            "token_endpoint":"https://identity.example.test/token", "jwks_uri":"https://identity.example.test/jwks",
            "response_types_supported":["code"], "subject_types_supported":["pairwise"],
            "id_token_signing_alg_values_supported":["HS256","none"]
        })).unwrap();
        let oidc: Oidc = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new("mdm".into()),
            Some(ClientSecret::new("secret".into())),
        );
        let now =
            rss_identity_client::Clock::unix_seconds(&rss_identity_client::SystemClock).unwrap();
        let payload=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"iss":"https://identity.example.test","aud":"mdm","sub":"subject","iat":now,"exp":now+300,"nonce":"nonce"})).unwrap());
        for alg in ["HS256", "none"] {
            let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{alg}"}}"#));
            let input = format!("{header}.{payload}");
            let signature = if alg == "HS256" {
                URL_SAFE_NO_PAD.encode(
                    CoreHmacKey::new("secret")
                        .sign(&CoreJwsSigningAlgorithm::HmacSha256, input.as_bytes())
                        .unwrap(),
                )
            } else {
                String::new()
            };
            let token: CoreIdToken = format!("{input}.{signature}").parse().unwrap();
            assert!(
                token
                    .claims(&verifier(&oidc), &Nonce::new("nonce".into()))
                    .is_err(),
                "discovery enabled symmetric token"
            );
        }
    }
}
