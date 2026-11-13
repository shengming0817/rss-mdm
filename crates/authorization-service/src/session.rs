use crate::credential::RequestCredential;
use crate::{
    Error, Store,
    context::{AuthorizedPrincipal, Principal},
};
use rss_identity_postgres::{Authority, AuthorityError};
pub use rss_identity_postgres::{RevalidatedSession, SessionReference};
use rss_request_context::TenantId;
/// Configured at composition time; request bodies cannot select a tenant or authority.
#[derive(Clone)]
pub struct SessionAuthority {
    authority: Authority,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
}
impl SessionAuthority {
    pub fn new(
        authority: Authority,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Self {
        Self { authority, binding }
    }
    pub fn binding(&self) -> rss_transactional_messaging::fence::ExecutionBinding {
        self.binding
    }
    pub fn tenant(&self) -> TenantId {
        self.binding.tenant()
    }
    /// Recheck the trusted operation's locator without retaining credentials or renewing idle.
    pub async fn recheck(
        &self,
        reference: &SessionReference,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<RevalidatedSession, Error> {
        self.authority
            .recheck_session_reference(self.binding, reference, deadline)
            .await
            .map_err(authority_error)
    }
    pub async fn authenticate(
        &self,
        store: &Store,
        credential: RequestCredential,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<AuthorizedPrincipal, Error> {
        let principal = match credential {
            RequestCredential::Cookie(secret) => Principal::new(
                self.authority
                    .inspect_session(self.binding, secret, deadline)
                    .await
                    .map_err(authority_error)?,
            )?,
            RequestCredential::Bearer(secret) => Principal::new(
                self.authority
                    .inspect_bearer(self.binding, secret, deadline)
                    .await
                    .map_err(authority_error)?,
            )?,
            RequestCredential::ApiKey(secret) => {
                store
                    .authenticate_key(&self.binding.tenant().to_string(), &secret)
                    .await?
            }
        };
        AuthorizedPrincipal::from_identity(store, principal)?
            .load_authorization(store)
            .await
    }
}

pub(crate) fn authority_error(error: AuthorityError) -> Error {
    match error {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::DeadlineElapsed => Error::Deadline,
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Storage,
    }
}

/// A retained identity remains a proof owned by Identity; audit fields never grant authority.
pub fn bind_revalidated_audit(
    facts: &RevalidatedSession,
    audit: &rss_mdm_audit_integration::RequestAudit,
) -> Result<(), Error> {
    facts.check_live().map_err(|_| Error::Unauthorized)?;
    if audit.tenant() != facts.account().tenant.to_string() {
        return Err(Error::Forbidden);
    }
    audit.set_principal(
        &facts.account().principal.as_uuid().to_string(),
        &facts.instance().to_string(),
    );
    Ok(())
}
