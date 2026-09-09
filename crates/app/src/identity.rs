//! Standard OIDC client plus the sole upstream online verifier.
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
struct Http {
    client: reqwest::Client,
    origin: url::Origin,
}
impl Http {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let url = url::Url::parse(&request.uri().to_string()).map_err(|_| Error::Unavailable)?;
        if url.origin() != self.origin
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Unavailable);
        }
        let mut response = self
            .client
            .request(request.method().clone(), url)
            .headers(request.headers().clone())
            .body(request.into_body())
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        let mut builder = axum::http::Response::builder().status(response.status());
        *builder.headers_mut().ok_or(Error::Unavailable)? = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len() + chunk.len() > 65536 {
                return Err(Error::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        builder.body(bytes).map_err(|_| Error::Unavailable)
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
        let oidc_secret = config::secret(&c.identity.oidc_secret_file)?;
        let validation = config::secret(&c.identity.validation_secret_file)?;
        if crate::sessions::equal(&oidc_secret, &validation) {
            return Err(Error::Configuration);
        }
        let ca = config::read(&c.identity.ca_file, 1024 * 1024, false)?;
        let http = Http {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .add_root_certificate(
                    reqwest::Certificate::from_pem(&ca).map_err(|_| Error::Configuration)?,
                )
                .build()
                .map_err(|_| Error::Configuration)?,
            origin: config::https_url(&c.identity.issuer)?.origin(),
        };
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(c.identity.issuer.clone()).map_err(|_| Error::Configuration)?,
            &http,
        )
        .await
        .map_err(|_| Error::Unavailable)?;
        for endpoint in [
            Some(metadata.authorization_endpoint().url()),
            metadata.token_endpoint().map(|u| u.url()),
            Some(metadata.jwks_uri().url()),
        ] {
            if !endpoint.is_some_and(|u| u.origin() == http.origin && u.scheme() == "https") {
                return Err(Error::Configuration);
            }
        }
        let oidc = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(c.identity.client_id.clone()),
            Some(ClientSecret::new(oidc_secret.to_string())),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/auth/callback", c.product_origin))
                .map_err(|_| Error::Configuration)?,
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
        .map_err(|_| Error::Configuration)?;
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
            .map_err(|_| Error::Configuration)?
            .set_pkce_verifier(pending.verifier)
            .request_async(&self.http)
            .await
            .map_err(|error| match error {
                RequestTokenError::ServerResponse(response)
                    if matches!(response.error(), CoreErrorResponseType::InvalidGrant) =>
                {
                    Error::Unauthorized
                }
                _ => Error::Unavailable,
            })?;
        let id = response.id_token().ok_or(Error::Unauthorized)?;
        let claims = id
            .claims(&self.oidc.id_token_verifier(), &pending.nonce)
            .map_err(|_| Error::Unauthorized)?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                id.signing_alg().map_err(|_| Error::Unauthorized)?,
                id.signing_key(&self.oidc.id_token_verifier())
                    .map_err(|_| Error::Unauthorized)?,
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
    if let E::Server {
        code,
        correlation_id,
    } = &error
    {
        eprintln!("component=identity_validate code={code:?} correlation_id={correlation_id}");
    }
    match error {
        E::Rejected
        | E::Server {
            code:
                rss_identity_contracts::ValidationFailureCode::InvalidCredential
                | rss_identity_contracts::ValidationFailureCode::IdentityNotActive,
            ..
        } => Error::Unauthorized,
        _ => Error::Unavailable,
    }
}
