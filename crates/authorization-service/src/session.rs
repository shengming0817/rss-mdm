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
        credential: RequestCredential,
    ) -> Result<AuthorizedPrincipal, Error> {
        let deadline = rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            std::time::Duration::from_secs(10),
        );
        let principal = match credential {
            RequestCredential::Cookie(secret) => Principal::new(
                self.authority
                    .inspect_session(self.tenant, secret, deadline)
                    .await
                    .map_err(authority_error)?,
            )?,
            RequestCredential::Bearer(secret) => Principal::new(
                self.authority
                    .inspect_bearer(self.tenant, secret, deadline)
                    .await
                    .map_err(authority_error)?,
            )?,
            RequestCredential::ApiKey(secret) => {
                store
                    .authenticate_key(&self.tenant.to_string(), &secret)
                    .await?
            }
        };
        AuthorizedPrincipal::from_identity(principal)
            .load_authorization(store)
            .await
    }
}

pub(crate) fn authority_error(error: AuthorityError) -> Error {
    match error {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
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
