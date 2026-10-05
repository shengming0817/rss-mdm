//! Native authentication consumes Identity proofs without creating a browser session.
pub use rss_identity_core::entra::{EntraTokenProfile, EntraTokenVerifier};
pub use rss_identity_postgres::{EntraAuthority, RevalidatedAccount, VerifiedExternalSubject};
pub async fn verify(
    authority: &EntraAuthority,
    token: zeroize::Zeroizing<String>,
) -> Result<VerifiedExternalSubject, crate::Error> {
    authority
        .verify(token, deadline())
        .await
        .map_err(authority_error)
}
pub async fn resolve(
    authority: &EntraAuthority,
    subject: VerifiedExternalSubject,
) -> Result<RevalidatedAccount, crate::Error> {
    authority
        .resolve(subject, deadline())
        .await
        .map_err(authority_error)
}
pub async fn recheck(
    authority: &EntraAuthority,
    account: RevalidatedAccount,
) -> Result<RevalidatedAccount, crate::Error> {
    authority
        .recheck(account, deadline())
        .await
        .map_err(authority_error)
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(10),
    )
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
