//! Native authentication consumes Identity proofs without creating a browser session.
pub use rss_identity_core::entra::{EntraTokenProfile, EntraTokenVerifier};
pub use rss_identity_postgres::{EntraAuthority, RevalidatedAccount, VerifiedExternalSubject};
pub async fn verify(
    authority: &EntraAuthority,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    token: zeroize::Zeroizing<String>,
    deadline: rss_request_context::Deadline,
) -> Result<VerifiedExternalSubject, crate::Error> {
    authority
        .verify(binding, token, deadline)
        .await
        .map_err(authority_error)
}
pub async fn resolve(
    authority: &EntraAuthority,
    subject: VerifiedExternalSubject,
    deadline: rss_request_context::Deadline,
) -> Result<RevalidatedAccount, crate::Error> {
    authority
        .resolve(subject, deadline)
        .await
        .map_err(authority_error)
}
pub async fn recheck(
    authority: &EntraAuthority,
    account: RevalidatedAccount,
    deadline: rss_request_context::Deadline,
) -> Result<RevalidatedAccount, crate::Error> {
    authority
        .recheck(account, deadline)
        .await
        .map_err(authority_error)
}

fn authority_error(error: rss_identity_postgres::AuthorityError) -> crate::Error {
    use rss_identity_core::federation::FederationError;
    match error {
        rss_identity_postgres::AuthorityError::Federation(
            FederationError::Claims
            | FederationError::Rejected
            | FederationError::StaleConfiguration,
        ) => crate::Error::Unauthorized,
        other => crate::session::authority_error(other),
    }
}
