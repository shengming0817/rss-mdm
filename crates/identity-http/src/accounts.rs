use crate::transport::*;
use crate::{ACTION, Declaration, IDENTITY, Route, Router, get, post, route_module};
// Instance-local management. Domain authorization is rechecked in the mutation transaction.
use crate::{AppState, boundary::*};
use axum::{
    Extension, Json,
    extract::{Path, Query, Request, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountRuleError, LoginKey, Password},
    federation::FederationError,
};
use rss_identity_postgres::{
    AccountView, AttemptSource, AuthenticatedSession, Authority, AuthorityError,
};
use rss_transactional_messaging::fence::ExecutionBinding;
use serde::{Deserialize, de::DeserializeOwned};

#[derive(Clone)]
struct Management {
    authority: Authority,
}
pub(crate) struct Error(HttpError);
impl From<rss_identity_web_credentials::CredentialError> for Error {
    fn from(e: rss_identity_web_credentials::CredentialError) -> Self {
        Self(e.into())
    }
}
impl From<HttpError> for Error {
    fn from(e: HttpError) -> Self {
        Self(e)
    }
}
impl From<AuthorityError> for Error {
    fn from(error: AuthorityError) -> Self {
        let code = match error {
            AuthorityError::CursorInvalidated => WireCode::AccountCursorInvalidated,
            AuthorityError::ProfileReceiptCapacityReached => {
                WireCode::ProfileReceiptCapacityReached
            }
            AuthorityError::ProfileOperationExpired => WireCode::ProfileOperationExpired,
            AuthorityError::RevisionConflict => WireCode::RevisionConflict,
            AuthorityError::OperationConflict => WireCode::OperationConflict,
            AuthorityError::Rejected => WireCode::InvalidCredential,
            AuthorityError::ReauthenticationFailed => WireCode::ReauthenticationFailed,
            AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege) => {
                WireCode::InsufficientPrivilege
            }
            AuthorityError::RuleRejected(AccountRuleError::AlreadyExists) => {
                WireCode::AccountAlreadyExists
            }
            AuthorityError::RuleRejected(AccountRuleError::ReauthenticationRequired) => {
                WireCode::ReauthenticationRequired
            }
            AuthorityError::RuleRejected(AccountRuleError::Rejected)
            | AuthorityError::InvalidInput
            | AuthorityError::Federation(FederationError::Configuration) => {
                WireCode::MalformedRequest
            }
            AuthorityError::Federation(FederationError::ProviderLimitReached) => {
                WireCode::ProviderLimitReached
            }
            AuthorityError::Federation(FederationError::StaleConfiguration) => {
                WireCode::ConfigurationChanged
            }
            AuthorityError::Federation(FederationError::Conflict) => WireCode::IdentityLinkConflict,
            AuthorityError::RateLimited { .. } => WireCode::RateLimited,
            _ => WireCode::IdentityUnavailable,
        };
        Self(HttpError(code, Some(crate::HttpFailure::Authority(error))))
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}
type Result<T> = std::result::Result<T, Error>;
/// Local account management, independent of upstream federation.
pub fn routes(state: Option<&AppState>) -> Router<(), impl Declaration + use<>> {
    route_module! { struct Accounts for [Browser] { accounts, create_account, read_account, enabled, membership, reset_password, own_password } }
    let routes = Accounts {
        accounts: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts",
            get(accounts, &IDENTITY, ACTION),
        ),
        create_account: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts",
            post(create_account, &IDENTITY, ACTION),
        ),
        read_account: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts/{principal}",
            get(read_account, &IDENTITY, ACTION),
        ),
        enabled: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts/{principal}/enabled",
            post(enabled, &IDENTITY, ACTION),
        ),
        membership: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts/{principal}/membership",
            post(membership, &IDENTITY, ACTION),
        ),
        reset_password: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts/{principal}/password",
            post(reset_password, &IDENTITY, ACTION),
        ),
        own_password: Route::new(
            "/api/v1/identity/tenants/{tenant}/account/password",
            post(own_password, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    crate::browser(routes, state, 32768).bind_with(state, |s| Management {
        authority: s.authority.clone(),
    })
}

pub(crate) async fn management_actor(
    authority: &Authority,
    binding: ExecutionBinding,
    h: &HeaderMap,
    b: Deadline,
    write: bool,
) -> Result<AuthenticatedSession> {
    let secret = cookie(h)?.ok_or(UNAUTH)?;
    if write {
        if !request_marker(h)? {
            return Err(FORBIDDEN.into());
        }
        csrf(h, &secret)?;
    }
    Ok(authority.inspect_session(binding, secret, b).await?)
}
pub(crate) async fn body<T: DeserializeOwned>(request: Request, b: Deadline) -> Result<T> {
    let bytes = read_body(request, b, |request| {
        axum::body::to_bytes(request.into_body(), 32768)
    })
    .await?;
    serde_json::from_slice(&bytes).map_err(|_| BAD.into())
}
fn target(t: &str, p: &str) -> Result<AccountKey> {
    Ok(AccountKey {
        tenant: tenant(t)?,
        principal: PrincipalId::parse(p).map_err(|_| BAD)?,
    })
}
fn password(s: String) -> Result<Password> {
    Password::new(s).map_err(|_| BAD.into())
}
fn account(state: rss_identity_core::account::AccountState) -> Json<crate::dto::Account> {
    Json(crate::dto::Account::from(AccountView::new(state, None)))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountParameters {
    filter: Option<String>,
    sort: Option<String>,
    fields: Option<String>,
    source: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}
async fn accounts(
    State(s): State<Management>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
    Headers(h): Headers<PASSIVE>,
    q: std::result::Result<Query<AccountParameters>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<crate::dto::AccountPage>> {
    let Query(page) = q.map_err(|_| BAD)?;
    let query = rss_identity_core::directory::AccountQuery::parse(
        page.filter.as_deref(),
        page.sort.as_deref(),
        page.fields.as_deref(),
        page.source.as_deref(),
        page.limit.unwrap_or(50),
    )
    .map_err(|_| BAD)?;
    let actor = management_actor(&s.authority, binding, &h, b, false).await?;
    Ok(Json(crate::dto::AccountPage::from(
        s.authority
            .list_accounts(actor, query, page.cursor, b)
            .await?,
    )))
}
async fn read_account(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Headers(h): Headers<PASSIVE>,
) -> Result<Json<crate::dto::Account>> {
    let actor = management_actor(&s.authority, binding, &h, b, false).await?;
    Ok(Json(crate::dto::Account::from(
        s.authority.read_account(actor, target(&t, &p)?, b).await?,
    )))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateAccount {
    login: String,
    password: String,
}
async fn create_account(
    State(s): State<Management>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<CreateAccount, WRITE>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<201, Json<crate::dto::Account>>> {
    let actor = management_actor(&s.authority, binding, r.headers(), b, true).await?;
    let v: CreateAccount = body(r, b).await?;
    let name = LoginKey::parse(&v.login).map_err(|_| BAD)?;
    let canonical_login = name.as_str().to_owned();
    let state = s
        .authority
        .create_local_account(actor, name, password(v.password)?, b)
        .await?;
    Ok(rss_mdm_http_contract::signature::WithStatus(Json(
        crate::dto::Account::from(AccountView::new(state, Some(canonical_login))),
    )))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Toggle {
    enabled: bool,
}
async fn enabled(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<Toggle, WRITE>,
) -> Result<Json<crate::dto::Account>> {
    let actor = management_actor(&s.authority, binding, r.headers(), b, true).await?;
    let v: Toggle = body(r, b).await?;
    Ok(account(
        s.authority
            .set_account_enabled(actor, target(&t, &p)?, v.enabled, b)
            .await?,
    ))
}
async fn membership(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<Toggle, WRITE>,
) -> Result<Json<crate::dto::Account>> {
    let actor = management_actor(&s.authority, binding, r.headers(), b, true).await?;
    let v: Toggle = body(r, b).await?;
    Ok(account(
        s.authority
            .set_account_membership(actor, target(&t, &p)?, v.enabled, b)
            .await?,
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reset {
    password: String,
}
async fn reset_password(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<Reset, WRITE>,
) -> Result<Json<crate::dto::Account>> {
    let actor = management_actor(&s.authority, binding, r.headers(), b, true).await?;
    let v: Reset = body(r, b).await?;
    Ok(account(
        s.authority
            .reset_local_password(actor, target(&t, &p)?, password(v.password)?, b)
            .await?,
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangePassword {
    current_password: String,
    password: String,
}
async fn own_password(
    State(s): State<Management>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
    Deferred(r, _): Deferred<ChangePassword, WRITE>,
) -> Result<Json<crate::dto::Account>> {
    let actor = management_actor(&s.authority, binding, r.headers(), b, true).await?;
    let peer = r
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(AuthorityError::Unavailable)?
        .0;
    let source = AttemptSource::parse(&peer.to_string())?;
    let v: ChangePassword = body(r, b).await?;
    Ok(account(
        s.authority
            .change_own_password(
                actor,
                password(v.current_password)?,
                password(v.password)?,
                source,
                b,
            )
            .await?,
    ))
}
impl rss_mdm_http_contract::signature::Output for Error {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        crate::error::describe_codes(&[
            WireCode::AccountAlreadyExists,
            WireCode::AccountCursorInvalidated,
            WireCode::ConfigurationChanged,
            WireCode::CsrfRejected,
            WireCode::IdentityLinkConflict,
            WireCode::IdentityUnavailable,
            WireCode::InsufficientPrivilege,
            WireCode::InvalidCredential,
            WireCode::MalformedRequest,
            WireCode::OperationConflict,
            WireCode::ProfileOperationExpired,
            WireCode::ProfileReceiptCapacityReached,
            WireCode::ProviderLimitReached,
            WireCode::RateLimited,
            WireCode::ReauthenticationFailed,
            WireCode::ReauthenticationRequired,
            WireCode::RevisionConflict,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    #[test]
    fn password_wire_rejects_retired_field_spelling() {
        assert!(
            serde_json::from_value::<ChangePassword>(
                serde_json::json!({"currentPassword":"old", "password":"new"})
            )
            .is_ok()
        );
        assert!(
            serde_json::from_value::<ChangePassword>(
                serde_json::json!({"current_password":"old", "password":"new"})
            )
            .is_err()
        );
    }
    #[test]
    fn management_rejections_are_not_login_failures() {
        for (error, status, code) in [
            (
                AuthorityError::Configuration,
                StatusCode::SERVICE_UNAVAILABLE,
                "identity_unavailable",
            ),
            (
                AuthorityError::DeadlineElapsed,
                StatusCode::SERVICE_UNAVAILABLE,
                "identity_unavailable",
            ),
            (
                AuthorityError::InvalidInput,
                StatusCode::BAD_REQUEST,
                "malformed_request",
            ),
            (
                AuthorityError::RuleRejected(AccountRuleError::Rejected),
                StatusCode::BAD_REQUEST,
                "malformed_request",
            ),
            (
                AuthorityError::Rejected,
                StatusCode::UNAUTHORIZED,
                "invalid_credential",
            ),
            (
                AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege),
                StatusCode::FORBIDDEN,
                "insufficient_privilege",
            ),
            (
                AuthorityError::ReauthenticationFailed,
                StatusCode::FORBIDDEN,
                "reauthentication_failed",
            ),
            (
                AuthorityError::RuleRejected(AccountRuleError::ReauthenticationRequired),
                StatusCode::FORBIDDEN,
                "reauthentication_required",
            ),
        ] {
            let value = Error::from(error);
            assert_eq!(value.0.0.status(), status);
            assert_eq!(serde_json::to_value(value.0.0).unwrap(), code);
        }
    }
}
