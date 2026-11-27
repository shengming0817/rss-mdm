use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rss_identity_postgres::AuthorityError;
use rss_identity_web_credentials::CredentialError;
/// Non-secret response extension for host diagnostics; never included in the public body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    Authority(AuthorityError),
    RequestTimeout,
}
#[derive(Debug)]
pub struct HttpError(pub(crate) WireCode, pub(crate) Option<HttpFailure>);
pub(crate) const BAD: HttpError = HttpError(WireCode::MalformedRequest, None);
pub(crate) const UNAUTH: HttpError = HttpError(WireCode::InvalidCredential, None);
pub(crate) const FORBIDDEN: HttpError = HttpError(WireCode::CsrfRejected, None);
impl HttpError {
    pub(crate) fn request_timeout() -> Self {
        Self(
            WireCode::IdentityUnavailable,
            Some(HttpFailure::RequestTimeout),
        )
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let mut response = (self.0.status(), Json(ErrorBody { code: self.0 })).into_response();
        response.headers_mut().insert(
            header::REFERRER_POLICY,
            header::HeaderValue::from_static("no-referrer"),
        );
        if let Some(HttpFailure::Authority(AuthorityError::RateLimited {
            retry_after_seconds,
        })) = self.1
        {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                axum::http::HeaderValue::from(retry_after_seconds.get()),
            );
        }
        if let Some(class) = self.1 {
            response.extensions_mut().insert(class);
        }
        response
    }
}
impl From<AuthorityError> for HttpError {
    fn from(error: AuthorityError) -> Self {
        let mut response = match error {
            AuthorityError::InteractionRequired => Self(WireCode::InteractionRequired, None),
            AuthorityError::Cancelled => Self(WireCode::AuthenticationCancelled, None),
            AuthorityError::InvalidInput => BAD,
            AuthorityError::Federation(error) => match error {
                rss_identity_core::federation::FederationError::Configuration => BAD,
                rss_identity_core::federation::FederationError::Conflict => {
                    Self(WireCode::IdentityLinkConflict, None)
                }
                rss_identity_core::federation::FederationError::StaleConfiguration => {
                    Self(WireCode::ConfigurationChanged, None)
                }
                rss_identity_core::federation::FederationError::Unavailable => {
                    Self(WireCode::IdentityUnavailable, None)
                }
                rss_identity_core::federation::FederationError::Provider(f) => {
                    use rss_identity_core::federation::{ProviderReason, ProviderStage};
                    if f.stage == ProviderStage::Exchange
                        && f.reason == ProviderReason::CodeRejected
                    {
                        UNAUTH
                    } else {
                        Self(WireCode::IdentityUnavailable, None)
                    }
                }
                _ => UNAUTH,
            },
            AuthorityError::Rejected | AuthorityError::RuleRejected(_) => UNAUTH,
            AuthorityError::RateLimited { .. } => Self(WireCode::RateLimited, None),
            _ => Self(WireCode::IdentityUnavailable, None),
        };
        response.1 = Some(HttpFailure::Authority(error));
        response
    }
}

impl From<CredentialError> for HttpError {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::Malformed => BAD,
            CredentialError::Invalid => UNAUTH,
            CredentialError::Forbidden => FORBIDDEN,
            CredentialError::Deadline => Self::request_timeout(),
            CredentialError::Authority(e) => Self::from(e),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WireCode {
    AccountAlreadyExists,
    AccountCursorInvalidated,
    AuthenticationCancelled,
    ConfigurationChanged,
    CsrfRejected,
    IdentityLinkConflict,
    IdentityUnavailable,
    InsufficientPrivilege,
    InteractionRequired,
    InvalidCredential,
    MalformedRequest,
    OperationConflict,
    ProfileOperationExpired,
    ProfileReceiptCapacityReached,
    ProviderLimitReached,
    RateLimited,
    ReauthenticationFailed,
    ReauthenticationRequired,
    RevisionConflict,
}
impl WireCode {
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::MalformedRequest => StatusCode::BAD_REQUEST,
            Self::AccountAlreadyExists
            | Self::AccountCursorInvalidated
            | Self::AuthenticationCancelled
            | Self::ConfigurationChanged
            | Self::IdentityLinkConflict
            | Self::OperationConflict
            | Self::ProfileReceiptCapacityReached
            | Self::ProviderLimitReached
            | Self::RevisionConflict => StatusCode::CONFLICT,
            Self::CsrfRejected
            | Self::InsufficientPrivilege
            | Self::InteractionRequired
            | Self::ReauthenticationFailed
            | Self::ReauthenticationRequired => StatusCode::FORBIDDEN,
            Self::ProfileOperationExpired => StatusCode::GONE,
            Self::IdentityUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::InvalidCredential => StatusCode::UNAUTHORIZED,
        }
    }
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub(crate) struct ErrorBody {
    code: WireCode,
}
pub(crate) fn describe_codes(
    codes: &[WireCode],
) -> Vec<rss_mdm_http_contract::signature::Response> {
    use rss_mdm_http_contract::signature::{Response, Schema};
    codes
        .iter()
        .map(|code| {
            let mut r = Response::json::<ErrorBody>(code.status().as_u16());
            r.body.as_mut().expect("JSON error body").schema.value["properties"]["code"] =
                serde_json::json!({"const":code});
            let mut privacy = Schema::response::<String>();
            privacy.value["const"] = "no-referrer".into();
            r.headers.insert("referrer-policy".into(), privacy);
            if matches!(code, WireCode::RateLimited) {
                r.headers
                    .insert("retry-after".into(), Schema::response::<String>());
            }
            r
        })
        .collect()
}
impl rss_mdm_http_contract::signature::Output for HttpError {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        describe_codes(&[
            WireCode::AuthenticationCancelled,
            WireCode::ConfigurationChanged,
            WireCode::CsrfRejected,
            WireCode::IdentityLinkConflict,
            WireCode::IdentityUnavailable,
            WireCode::InteractionRequired,
            WireCode::InvalidCredential,
            WireCode::MalformedRequest,
            WireCode::RateLimited,
        ])
    }
}

/// Failures returned when inspecting credentials on a product route.
pub fn credential_rejections() -> Vec<rss_mdm_http_contract::signature::Response> {
    describe_codes(&[
        WireCode::MalformedRequest,
        WireCode::InvalidCredential,
        WireCode::CsrfRejected,
        WireCode::RateLimited,
        WireCode::IdentityUnavailable,
    ])
}
