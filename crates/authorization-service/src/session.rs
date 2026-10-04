use crate::{
    Error, Store,
    context::{AuthorizedPrincipal, Principal},
};
use rss_identity_core::session::SessionSecret;
use rss_identity_postgres::{Authority, AuthorityError};
pub use rss_identity_postgres::{RevalidatedSession, SessionReference};
use rss_request_context::TenantId;
/// Configured at composition time; request bodies cannot select a tenant or authority.
#[derive(Clone)]
pub struct SessionAuthority {
    authority: Authority,
    tenant: TenantId,
}
impl SessionAuthority {
    pub fn new(authority: Authority, tenant: TenantId) -> Self {
        Self { authority, tenant }
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Recheck the trusted operation's locator without retaining credentials or renewing idle.
    pub async fn recheck(&self, reference: &SessionReference) -> Result<RevalidatedSession, Error> {
        self.authority
            .recheck_session_reference(
                self.tenant,
                reference,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    std::time::Duration::from_secs(10),
                ),
            )
            .await
            .map_err(authority_error)
    }
    pub async fn authenticate(
        &self,
        store: &Store,
        secret: SessionSecret,
    ) -> Result<AuthorizedPrincipal, Error> {
        let deadline = rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            std::time::Duration::from_secs(10),
        );
        let session = self
            .authority
            .inspect_session(self.tenant, secret, deadline)
            .await
            .map_err(authority_error)?;
        AuthorizedPrincipal::from_identity(Principal::new(session)?)
            .load_authorization(store)
            .await
    }
}

fn authority_error(error: AuthorityError) -> Error {
    match error {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Storage,
    }
}
