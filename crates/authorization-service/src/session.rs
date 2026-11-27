/// Fixed RSS lock ports granted by grant_platform_subject_admission to the product role.
pub const PLATFORM_SUBJECT_ACCESS: &str = include_str!("platform-subject-access.json");
use crate::credential::RequestCredential;
use crate::{
    Error, Store,
    context::{AuthorizedPrincipal, Principal},
};
use rss_identity_postgres::{Authority, AuthorityError};
pub use rss_identity_postgres::{RevalidatedSession, SessionReference};
use rss_transactional_messaging::fence::ExecutionBinding;
/// Shared authentication owner. Every operation supplies its original execution binding.
#[derive(Clone)]
pub struct SessionAuthority {
    authority: Authority,
}
impl SessionAuthority {
    pub fn new(authority: Authority) -> Self {
        Self { authority }
    }
    /// Recheck the trusted operation's locator without retaining credentials or renewing idle.
    pub async fn recheck(
        &self,
        binding: ExecutionBinding,
        reference: &SessionReference,
        deadline: rss_request_context::Deadline,
    ) -> Result<RevalidatedSession, Error> {
        self.authority
            .recheck_session_reference(binding, reference, deadline)
            .await
            .map_err(authority_error)
    }
    pub async fn authenticate(
        &self,
        binding: ExecutionBinding,
        store: &Store,
        credential: RequestCredential,
        deadline: rss_request_context::Deadline,
    ) -> Result<AuthorizedPrincipal, Error> {
        let principal = match credential {
            RequestCredential::Cookie(secret) => Principal::new(
                &self.authority,
                self.authority
                    .inspect_session(binding, secret, deadline)
                    .await
                    .map_err(authority_error)?,
                binding,
            )?,
            RequestCredential::Bearer(secret) => Principal::new(
                &self.authority,
                self.authority
                    .inspect_bearer(binding, secret, deadline)
                    .await
                    .map_err(authority_error)?,
                binding,
            )?,
            RequestCredential::ApiKey(secret) => store.authenticate_key(binding, &secret).await?,
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
